package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"

	// "github.com/form3tech-oss/jwt-go"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

// Cfg configuration structure
type Cfg struct {
	Port                 int    `env:"PORT,default=8001" short:"p" long:"port" description:"HTTP Port"`
	DbURL                string `env:"DBURL,default=postgres://root@localhost:26257/tnes?sslmode=disable" long:"dbUrl" description:"Database connection URL"`
	JwksCertRenewMinutes int    `env:"JWKS_RENEW_MINUTES,default=60" description:"Number of minutes to wait before renewing JWKS certificates"`
	JWTIssuer            string `env:"JWT_ISSUER" description:"The URL to the JWT issuing server"`
	AuditTrailURL        string `env:"AUDIT_TRAIL_URL,default=http://localhost:8080" description:"Audit trail app URL"`
	AuditTrailAPIKey     string `env:"AUDIT_TRAIL_API_KEY" description:"API key will be used to create audit records"`
	InteliquentBasePath  string `env:"INTELIQUENT_BASE_PATH" default:"https://services.inteliquent.com/Services/1.0.0/" description:"Inteliquent API service endpoint"`
	InteliquentAPIKey    string `env:"INTELIQUENT_API_KEY" description:"API key for Inteliquent service"`
	InteliquentSecretKey string `env:"INTELIQUENT_SECRET_KEY" description:"SECRET_KEY for Inteliquent service"`
}

// Jwks struct
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys struct
type JSONWebKeys struct {
	Kty string   `json:"kty"` // Key Type
	Kid string   `json:"kid"` // Key ID
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"` // x.509 Certificate Chain
	// Alg string `json:"alg"` // Message authentication code algorithm
	// X5t  string `json:"x5t"`
	//X5trs256 string
}

type server struct {
	// db         models.TNOperations
	httpClient *http.Client
	// iqnt       iqnt.API
	config *Cfg
	root   http.Handler
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.root.ServeHTTP(w, r)
}

type JWTErr struct {
	Status int
	Msg    string
}

func (jwte *JWTErr) StatusCode() int {
	return jwte.Status
}
func (jwte *JWTErr) Error() string {
	return jwte.Msg
}

type ErrResponse struct {

	// The HTTP response code
	HTTPStatusCode int `json:"HTTPStatusCode"`

	// The message explaining the error
	Msg string `json:"msg"`

	// The request id to track errors
	RequestID string `json:"requestID"`
}

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

// JWTErrorHandler formatts JWT validation errors with the builtin error
// response.  This is passed to the JWTMiddleware
// func(w http.ResponseWriter, r *http.Request, err string)

func JWTErrorHandler(w http.ResponseWriter, r *http.Request, err string) {
	jerr := &JWTErr{Status: http.StatusUnauthorized, Msg: err}
	ctx := r.Context()
	ErrorEncoder(ctx, jerr, w)
	return
}

var jwks = Jwks{}

func ErrorEncoder(ctx context.Context, err error, w http.ResponseWriter) {
	log.Ctx(ctx).Error().Err(err).Send()
	reqID, _ := hlog.IDFromCtx(ctx)
	w.Header().Set("Content-Type", "application/json")
	if headerer, ok := err.(openapi3filter.Headerer); ok {
		for k, values := range headerer.Headers() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
	}

	code := http.StatusInternalServerError
	if sc, ok := err.(openapi3filter.StatusCoder); ok {
		code = sc.StatusCode()
	}
	if code == 401 {
		w.Header().Add("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(code)
	body, _ := json.Marshal(&ErrResponse{
		HTTPStatusCode: code,
		Msg:            err.Error(),
		RequestID:      reqID.String(),
	})

	w.Write(body)
}

// FetchJWTKeySet stores keycloak jwt key set
func FetchJWTKeySet(cfg *Cfg) error {
	log.Info().Msg("Updating JWT Key set from the server...")
	resp, err := http.Get(cfg.JWTIssuer + "/protocol/openid-connect/certs")

	if err != nil {
		log.Error().Msg(err.Error())
		// ErrorCounter.Inc()
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		log.Error().Msg(err.Error())
		// ErrorCounter.Inc()
		return err
	}

	log.Info().Msg("JWT Key set loaded successfully.")
	return nil
}

// RefreshJWTKS refreshes jwt key set from the server
func RefreshJWTKS(cfg *Cfg) {
	refreshInterval := cfg.JwksCertRenewMinutes
	if refreshInterval != 0 {
		duration := time.Duration(refreshInterval) * time.Minute

		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

		go func(d time.Duration) {
			ticker := time.NewTicker(d)
			defer ticker.Stop()
		refreshLoop:
			for {
				select {
				case <-ticker.C:
					FetchJWTKeySet(cfg)
				case <-shutdown:
					break refreshLoop
				}
			}
		}(duration)
	}
}
func (s *server) JWTAuthentication001(next http.Handler) http.Handler {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := s.config.JWTIssuer

		if issuer != "" {
			jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{})

			err := jwtMiddleware.CheckJWT(w, r)

			// If there was an error, do not continue.
			if err != nil {
				return
			}
		}

		next.ServeHTTP(w, r)
	})
	return fn
}

// JWTAuthentication middleware from auth.go
func (s *server) JWTAuthentication(next http.Handler) http.Handler {
	log.Debug().Msg("JWTAuthentication - entering")
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := s.config.JWTIssuer

		if issuer != "" {
			jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
				ErrorHandler: JWTErrorHandler,
				Debug:        true,
				ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
					// Verify 'iss' claim
					checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
					if !checkIss {
						return token, errors.New("invalid issuer")
					}

					publicKey, err := getPemCert(token)
					if err != nil {
						return nil, err
					}

					r = setUser(token, r)

					// r = getRole(token, r)
					r = getRoles(token, r)
					r = getGroups(token, r)
					result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

					return result, nil
				},
				SigningMethod: jwt.SigningMethodRS256,
			})

			err := jwtMiddleware.CheckJWT(w, r)

			// If there was an error, do not continue.
			if err != nil {

				return
			}
		}

		next.ServeHTTP(w, r)
	})

	return fn
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}

// setUser from auth.go
func setUser(token *jwt.Token, r *http.Request) *http.Request {
	log.Debug().Msg("setUser - entering")
	claims := token.Claims.(jwt.MapClaims)
	fmt.Printf("claims: %#v\n", claims)
	ctx := context.WithValue(r.Context(), "user", claims["email"])
	return r.WithContext(ctx)
}

// getRole from auth.go
func getRole(token *jwt.Token, r *http.Request) *http.Request {
	log.Debug().Msg("getRole - entering")
	claims := token.Claims.(jwt.MapClaims)
	ctx := context.WithValue(r.Context(), "role", claims["role"])
	return r.WithContext(ctx)
}

// getRoles - new function for JWT roles
func getRoles001(token *jwt.Token, r *http.Request) *http.Request {
	log.Debug().Msg("getRoles - entering")
	var roles []string

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if resourceAccess, ok := claims["resource_access"]; ok {
			if account, ok := resourceAccess.(map[string]interface{})["account"]; ok {
				if iRoles, ok := account.(map[string]interface{})["roles"].([]interface{}); ok {
					log.Printf("iRoles: %#v\n", iRoles)
					for _, role := range iRoles {
						if sRole, ok := role.(string); ok {
							roles = append(roles, sRole)
						}
					}
				}
			}
		}
	}

	log.Printf("roles: %#v\n", roles)
	ctx := context.WithValue(r.Context(), "roles", roles)
	return r.WithContext(ctx)
}

// getRoles - new function for JWT roles
func getRoles(token *jwt.Token, r *http.Request) *http.Request {
	log.Debug().Msg("getRoles - entering")
	var roles []string

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if realmAccess, ok := claims["realm_access"]; ok {
			if iRoles, ok := realmAccess.(map[string]interface{})["roles"].([]interface{}); ok {
				log.Printf("iRoles: %#v\n", iRoles)
				for _, role := range iRoles {
					if sRole, ok := role.(string); ok {
						roles = append(roles, sRole)
					}
				}
			}
		}
	}

	log.Printf("roles: %#v\n", roles)
	ctx := context.WithValue(r.Context(), "roles", roles)
	return r.WithContext(ctx)
}

func getGroups(token *jwt.Token, r *http.Request) *http.Request {
	var groups []string

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if iGroups, ok := claims["groups"].([]interface{}); ok {
			log.Printf("iGroups: %#v\n", iGroups)
			for _, group := range iGroups {
				if sGroup, ok := group.(string); ok {
					groups = append(groups, sGroup)
				}
			}
		}
	}

	log.Printf("groups: %#v\n", groups)
	ctx := context.WithValue(r.Context(), "groups", groups)
	return r.WithContext(ctx)
}

// checkRole from serverImpl.go
func checkRole(roleInfo interface{}) bool {
	if roleInfo != nil {
		roleClaim := roleInfo.([]interface{})
		role := roleClaim[0].(string)

		if role == "admin" {
			return true
		}
	}
	return false
}

// checkForRole - new function
func checkForRole(roles []string, role string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// checkForGroup - new function
func checkForGroup(groups []string, group string) bool {
	for _, g := range groups {
		if strings.EqualFold(g, group) {
			return true
		}
	}
	return false
}

// checkForAdminRole - new function
func checkForAdminRole(roles []string) bool {
	return checkForRole(roles, "admin")
}
func apiRouter(s *server) chi.Router {
	// If you are service is behind load balancer like nginx, you might want to
	// use X-Request-ID instead of injecting request id. You can do some thing
	// like this,
	// r.Use(hlog.CustomHeaderHandler("reqId", "X-Request-Id"))
	// sentryHandler := sentryhttp.New(sentryhttp.Options{
	// 	Repanic:         true,
	// 	WaitForDelivery: true,
	// 	// Timeout for the event delivery requests.
	// 	Timeout: 3})

	r := chi.NewRouter()
	// r.Use(middleware.Recoverer)
	// r.Use(hlog.NewHandler(log.Logger))
	// r.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
	// 	hlog.FromRequest(r).Info().
	// 		Str("method", r.Method).
	// 		Str("url", r.URL.String()).
	// 		Int("status", status).
	// 		Int("size", size).
	// 		Dur("duration", duration).
	// 		Msg("")
	// }))
	// r.Use(hlog.RequestIDHandler("req_id", "Request-Id"))
	// r.Use(hlog.RemoteAddrHandler("ip"))
	// r.Use(hlog.UserAgentHandler("user_agent"))
	// r.Use(hlog.RefererHandler("referer"))
	// r.Use(mwMetrics)
	// r.Use(Recoverer)

	r.Use(s.JWTAuthentication)
	// r.Use(sentryHandler.Handle)
	// r.Use(EventEnhancer)
	// handler := HandlerFromMux(s, r)

	// r.Handle("/", handler)
	return r
}

func (s *server) apidocs(w http.ResponseWriter, r *http.Request) {
	ctx := setContext(w, r)
	// role := ctx.Value("role")
	issuer := s.config.JWTIssuer
	// isAdmin := checkRole(role)
	var (
		roles []string
		ok    bool
	)
	if roles, ok = ctx.Value("roles").([]string); !ok {
		log.Error().Msg("apidocs - no roles")
	}
	isAdmin := checkForAdminRole(roles)

	if issuer == "" || isAdmin {
		html := `
<!doctype html> <!-- Important: must specify -->
<html>
<head>
  <meta charset="utf-8"> <!-- Important: rapi-doc uses utf8 charecters -->
  <script type="module" src="https://unpkg.com/rapidoc/dist/rapidoc-min.js"></script>
</head>
<body>
</dl>
  <rapi-doc
    spec-url = "openapi.json"
    show-header = 'false'
  > </rapi-doc>
</body>
</html>
`
		render.HTML(w, r, html)
	}
}
func ErrNotFound(r *http.Request, err error) render.Renderer {
	hlog.FromRequest(r).Error().Err(err).Send()
	reqID, _ := hlog.IDFromRequest(r)
	return &ErrResponse{
		HTTPStatusCode: http.StatusNotFound,
		Msg:            err.Error(),
		RequestID:      reqID.String(),
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	render.Render(w, r, ErrNotFound(r, errors.New("Not Found")))
}

// ping is handler responding to health-check request
func ping(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "pong")
}

func setContext(w http.ResponseWriter, r *http.Request) context.Context {
	ctx := context.WithValue(context.Background(), "requestID", w.Header().Get("Request-Id"))
	ctx = context.WithValue(ctx, "user", r.Context().Value("user"))
	// ctx = context.WithValue(ctx, "role", r.Context().Value("role"))
	ctx = context.WithValue(ctx, "roles", r.Context().Value("roles"))

	return ctx
}

// NewServer func
func NewServer(ctx context.Context, cfg *Cfg) (*server, error) {
	// var err error

	s := &server{
		config: cfg,
	}

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Logger.With().Timestamp().Caller().Logger()

	// db
	// s.db, err = models.InitializeDB(s.config)
	// if err != nil {
	// 	return nil, err
	// }

	// Create a new iqnt client
	// conf := s.config
	// s.iqnt = iqnt.New(conf.InteliquentAPIKey, conf.InteliquentSecretKey, conf.InteliquentBasePath)

	// configure http client for global usage
	s.httpClient = &http.Client{
		Timeout: time.Second * 10,
	}

	// routers, middlewares
	r := chi.NewRouter()

	// TODO: Add jwt-go-middleware to validate JWT.  For the ValidationKeyGetter see https://auth0.com/docs/quickstart/backend/golang/01-authorization
	// jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
	// 	ErrorHandler:        JWTErrorHandler,
	// 	CredentialsOptional: false,
	// 	Debug:               true,
	// 	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
	// 		secret := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/mAP0uVZQcYC3JtDCjelfZwqNp3kbOsBG2d2ILcDIEUEMs2VnTgTaMHky2/3dLF/wVYpD3ObNquIJslwdxrxxyXBoNKEkzdI34UgjB+ZcX7S++THLyg7bAkEMAn9jGK3wnPHpgK5Karxnu5dCBU6QPocekWeu5ibQr8gnxiaR4WdsYZhaRwRD0VvH1kSOtx2ceYnmtRACJv3MtPraJxUmVsa7Yzu8GRCd+EqeKRMkX/p8hNCdws04t9dO3AemVGI2gGAwJ3d16yPNd0hFWFOF58CVTD6fyDqPqE74DhSzBrJmggEkaxehLUpUofvP9WPrQz8YsDyMGjqByun+8VHQIDAQAB"
	// 		return []byte(secret), nil
	// 	},
	// 	SigningMethod: jwt.SigningMethodRS256,
	// })

	r.Use(cors.New(cors.Options{
		AllowedOrigins:     []string{"*"},
		AllowedMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:     []string{"Link"},
		AllowCredentials:   true,
		OptionsPassthrough: false,
		MaxAge:             3599, // Maximum value not ignored by any of major browsers
	}).Handler)

	// r.Handle("/metrics", promhttp.Handler())

	// r.Mount("/v1", apiRouter(s))
	r.Use(s.JWTAuthentication)
	r.HandleFunc("/", notFoundHandler)

	// health check
	r.HandleFunc("/ping", ping)
	// r.HandleFunc("/openapi.json", spec)
	r.HandleFunc("/docs", s.apidocs)

	s.root = r

	return s, nil
}

func main() {
	cfg := &Cfg{JWTIssuer: "https://auth.magna5.cloud/auth/realms/Telecom", JwksCertRenewMinutes: 5, Port: 8001}

	if issuer := cfg.JWTIssuer; issuer != "" {
		// fetch JWT key set
		err := FetchJWTKeySet(cfg)
		if err != nil {
			//log.Fatal("failed to fetch JWT Key Set ", err)
			log.Fatal().Err(err).Msg("failed to fetch JWT Key Set ")
		}
		RefreshJWTKS(cfg)
	}

	// create server instance
	s, err := NewServer(context.Background(), cfg)

	if err != nil {
		// log.Fatal(err)
		log.Fatal().Err(err)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: s,
	}
	log.Printf("starting %s", server.Addr)
	log.Print(server.ListenAndServe())

	// time.Sleep(5 * time.Minute)
}
