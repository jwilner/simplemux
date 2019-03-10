package simplemux

import (
	"context"
	"net/http"
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
	engine := &engine{root: newNode()}

	return &Router{
		engine:         engine,
		routeStarter:   RouteBuilder{engine: engine},
		defaultHandler: http.NotFoundHandler(),
	}
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
				h.ServeHTTP(w, SetVars(req, vars))
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

func SetVars(r *http.Request, vars []string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), keyVars, vars))
}

func Vars(r *http.Request) []string {
	return r.Context().Value(keyVars).([]string)
}

type engine struct {
	root *node
}

func (e *engine) insert(r route) {
	node := e.root
	for _, segment := range strings.SplitAfter(r.path, "/") {
		if _, ok := node.children[segment]; !ok {
			node.children[segment] = newNode()
		}
		node = node.children[segment]
	}

	node.handlers = append(node.handlers, handler{
		Handler: r.handler,
		method:  r.method,
		filters: r.filters,
	})
}

func newNode() *node {
	return &node{
		children: make(map[string]*node),
	}
}

type node struct {
	children map[string]*node
	handlers []handler
}

func (e *engine) match(path string) ([]string, []handler) {
	var vars []string
	node := e.root
	for _, v := range strings.SplitAfter(path, "/") {
		node := node.children[v]
		if node == nil && len(v) > 0 {
			if v[len(v)-1] == '/' {
				if node = node.children["*/"]; node != nil {
					vars = append(vars, v[:len(v)-1])
				}
			} else {
				if node = node.children["*"]; node != nil {
					vars = append(vars, v)
				}
			}
		}
		if node == nil {
			return nil, nil
		}
	}
	return vars, node.handlers
}

type handler struct {
	http.Handler
	method  string
	filters []Filter
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
