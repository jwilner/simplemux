package simplemux

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

type FilterResult int

const (
	FilterContinue FilterResult = iota
	FilterStop
)

type Filter interface {
	Filter(*http.Request) FilterResult
}

type Middleware func(http.Handler) http.Handler

func New() *Router {
	engine := &engine{root: newNode(nil)}
	builder := RouteBuilder{engine: engine}

	return &Router{engine: engine, routeStarter: builder, defaultHandler: http.NotFoundHandler()}
}

// defines the valid ways of beginning a route
type routeStarter interface {
	OptSlash(bool) RouteBuilder
	Path(string) RouteBuilder
	Middleware(Middleware) RouteBuilder
	Filter(Filter) RouteBuilder
}

type Router struct {
	routeStarter
	engine         *engine
	defaultHandler http.Handler
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	vars, handlers := r.engine.match(req.RequestURI)

	for _, h := range handlers {
		if h.method == req.Method {
			var filtered bool // feels clearer than a named loop
			for _, f := range h.filters {
				if f.Filter(req) != FilterContinue {
					filtered = true
					break
				}
			}

			if !filtered {
				if len(vars) == 0 {
					h.ServeHTTP(w, req)
					return
				}

				// zip found vars and the handler's name for them
				varMap := make(map[string]string, len(vars))
				for i, val := range vars {
					varMap[h.names[i]] = val
				}

				h.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), keyVars, varMap)))
				return
			}
		}
	}

	r.defaultHandler.ServeHTTP(w, req)
}

type ctxKey int

const (
	keyVars ctxKey = 1
)

func Vars(r *http.Request) []string {
	return r.Context().Value(keyVars).([]string)
}

type engine struct {
	root *node
}

var regexpVar = regexp.MustCompile(`^{([^:}]+)(?::([^}/]+))?}/?$`)

func (e *engine) insert(r route) {
	node := e.root

	var varNames []string
	for _, segment := range strings.SplitAfter(r.path, "/") {
		if groups := regexpVar.FindStringSubmatch(segment); len(groups) > 0 {
			varNames = append(varNames, groups[1])
			trailingSlash := segment[len(segment)-1] == '/'
			if len(groups) == 3 {
				node = node.addChild(&regexpMatcher{
					reg:   regexp.MustCompile(groups[2]),
					slash: trailingSlash,
				})
			} else {
				node = node.addChild(wildCardMatcher(trailingSlash))
			}
		} else {
			node = node.addChild(stringMatcher(segment))
		}
	}

	node.handlers = append(node.handlers, handler{
		Handler: r.handler,
		method:  r.method,
		filters: r.filters,
		names:   varNames,
	})
}

func newNode(m matcher) *node {
	return &node{matcher: m}
}

type node struct {
	matcher
	children []*node
	handlers []handler
}

func (n *node) addChild(m matcher) *node {
	insertPos := len(n.children)

newMSwitch:
	switch newM := m.(type) {
	case stringMatcher:
		for i, child := range n.children {
			switch old := child.matcher.(type) {
			case stringMatcher:
				if newM == old {
					return child // no need for insert
				}
			case *regexpMatcher, wildCardMatcher:
				insertPos = i
				break newMSwitch
			}
		}
	case *regexpMatcher:
		for i, child := range n.children {
			switch old := child.matcher.(type) {
			case stringMatcher:
				// implicit continue
			case *regexpMatcher:
				if newM.reg.String() == old.reg.String() && newM.slash == old.slash {
					return child
				}
			case wildCardMatcher:
				insertPos = i
				break newMSwitch
			}
		}
	case wildCardMatcher:
		for _, child := range n.children {
			switch old := child.matcher.(type) {
			case stringMatcher, *regexpMatcher:
				// implicit continue
			case wildCardMatcher:
				if newM == old {
					return child
				}
			}
		}
	}

	child := newNode(m)

	children := make([]*node, len(n.children)+1, len(n.children)+1)
	copy(children, n.children[:insertPos])
	children[insertPos] = child
	copy(children[insertPos+1:], n.children[insertPos:])

	n.children = children

	return child
}

type matcher interface {
	match(s string) (string, bool)
}

type regexpMatcher struct {
	reg   *regexp.Regexp
	slash bool
}

func (r *regexpMatcher) match(s string) (string, bool) {
	if len(s) > 0 && (s[len(s)-1] == '/') != r.slash {
		return "", false
	}
	return "", r.reg.MatchString(s)
}

type stringMatcher string

func (sm stringMatcher) match(s string) (string, bool) {
	return "", s == string(sm)
}

type wildCardMatcher bool

func (wc wildCardMatcher) match(s string) (string, bool) {
	if l := len(s) - 1; l >= 0 && s[l] == '/' {
		if wc {
			return s[:l], true
		}
	} else if !wc {
		return s, false
	}
	return "", false
}

func (e *engine) match(path string) ([]string, []handler) {
	var vars []string
	node := e.root

	for _, segment := range strings.SplitAfter(path, "/") {
		for _, child := range node.children {
			if pathVar, ok := child.match(segment); ok {
				if pathVar != "" {
					vars = append(vars, pathVar)
				}
				node = child
			}
		}
		return nil, nil
	}

	return vars, node.handlers
}

type handler struct {
	http.Handler
	method  string
	filters []Filter
	names   []string
}

type route struct {
	method, path string
	filters      []Filter
	middlewares  []Middleware
	handler      http.Handler
}

const (
	buildFlagOptSlash = 1 << iota
)

type RouteBuilder struct {
	route

	engine *engine
	flags  int
}

func (rb RouteBuilder) Path(path string) RouteBuilder {
	rb.path += path
	return rb
}

func (rb RouteBuilder) Middleware(mw Middleware) RouteBuilder {
	rb.middlewares = appendMiddleware(rb.middlewares, mw)
	return rb
}

func (rb RouteBuilder) Filter(f Filter) RouteBuilder {
	rb.filters = appendFilter(rb.filters, f)
	return rb
}

func (rb RouteBuilder) OptSlash(opt bool) RouteBuilder {
	if opt {
		rb.flags |= buildFlagOptSlash
	} else {
		rb.flags &= ^buildFlagOptSlash
	}
	return rb
}

func (rb RouteBuilder) Handle(method string, handler http.Handler) {
	rb.method = method
	rb.handler = handler

	routes := []route{rb.route}

	if rb.flags&buildFlagOptSlash > 0 && routes[0].path != "" && routes[0].path != "/" {
		r2 := routes[0]
		if r2.path[len(r2.path)-1] == '/' {
			r2.path = r2.path[:len(r2.path)-1] // remove trailing slash
		} else {
			r2.path += "/"
		}
		routes = append(routes, r2)
	}

	for _, r := range routes {
		rb.engine.insert(r)
	}
}

func (rb RouteBuilder) HandleFunc(method string, f func(http.ResponseWriter, *http.Request)) {
	rb.Handle(method, http.HandlerFunc(f))
}

// appendMiddleware always copies the underlying array so you don't get any unpredictable behavior:
// https://play.golang.org/p/hSryz_-DN4e
func appendMiddleware(old []Middleware, elems ...Middleware) []Middleware {
	newOnes := make([]Middleware, len(old)+len(elems))
	copy(newOnes, old)
	copy(newOnes[len(old):], elems)
	return newOnes
}

// appendFilter always copies the underlying array so you don't get any unpredictable behavior:
// https://play.golang.org/p/hSryz_-DN4e
func appendFilter(old []Filter, elems ...Filter) []Filter {
	newOnes := make([]Filter, len(elems))
	copy(newOnes, old)
	copy(newOnes[len(old):], elems)
	return newOnes
}
