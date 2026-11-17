package secassess

import (
	"strings"
)

// The dependency-name-to-role table (depth plan W3.2). One row per package
// name (or name family, a trailing * meaning "starts with"), tagged with the
// ecosystem it is a name in, so a name that means different things in two
// ecosystems never crosses over. A package may match several rows (aiohttp is
// a client and a server). The table is small and honest: a miss is fine, a
// wrong claim is not, so a row exists only for a package whose role is not in
// doubt. Java rows are artifact ids (the group id is not read).

// The dependency roles, in the order the facts list them.
const (
	DepRoleAuth         = "auth"
	DepRoleCrypto       = "crypto"
	DepRoleORM          = "orm"
	DepRoleTemplate     = "template"
	DepRoleHTTPClient   = "http_client"
	DepRoleQueue        = "queue"
	DepRoleLLMSDK       = "llm_sdk"
	DepRoleMCPSDK       = "mcp_sdk"
	DepRoleWebFramework = "web_framework"
)

// DepRoleIDs lists the closed role ids in display order.
var DepRoleIDs = []string{
	DepRoleAuth, DepRoleCrypto, DepRoleORM, DepRoleTemplate, DepRoleHTTPClient, DepRoleQueue, DepRoleLLMSDK, DepRoleMCPSDK, DepRoleWebFramework,
}

// depRoleRule is one row: in ecosystem lang, a dependency whose normalised
// name equals match (or starts with it when match ends in *) has role (""
// none) and is the framework (""none).
type depRoleRule struct {
	lang      string
	match     string
	role      string
	framework string
}

// depRoleRules is THE table. Within a language the rows are grouped by role;
// the order of the framework ids it introduces is the closed framework list's
// order (ProjectFrameworkIDs).
var depRoleRules = []depRoleRule{
	// ---- node ----
	{"node", "express", DepRoleWebFramework, "express"},
	{"node", "fastify", DepRoleWebFramework, "fastify"},
	{"node", "koa", DepRoleWebFramework, "koa"},
	{"node", "@hapi/hapi", DepRoleWebFramework, "hapi"},
	{"node", "restify", DepRoleWebFramework, "restify"},
	{"node", "@nestjs/core", DepRoleWebFramework, "nestjs"},
	{"node", "next", DepRoleWebFramework, "nextjs"},
	{"node", "nuxt", DepRoleWebFramework, "nuxt"},
	{"node", "@sveltejs/kit", DepRoleWebFramework, "sveltekit"},
	{"node", "@remix-run/node", DepRoleWebFramework, "remix"},
	{"node", "@remix-run/react", "", "remix"},
	{"node", "hono", DepRoleWebFramework, "hono"},
	{"node", "sails", DepRoleWebFramework, "sails"},
	{"node", "@adonisjs/core", DepRoleWebFramework, "adonis"},
	{"node", "react", "", "react"},
	{"node", "vue", "", "vue"},
	{"node", "svelte", "", "svelte"},
	{"node", "@angular/core", "", "angular"},
	{"node", "astro", "", "astro"},
	{"node", "gatsby", "", "gatsby"},
	{"node", "passport", DepRoleAuth, ""},
	{"node", "passport-*", DepRoleAuth, ""},
	{"node", "@nestjs/passport", DepRoleAuth, ""},
	{"node", "@nestjs/jwt", DepRoleAuth, ""},
	{"node", "next-auth", DepRoleAuth, ""},
	{"node", "@auth/*", DepRoleAuth, ""},
	{"node", "better-auth", DepRoleAuth, ""},
	{"node", "lucia", DepRoleAuth, ""},
	{"node", "jsonwebtoken", DepRoleAuth, ""},
	{"node", "jose", DepRoleAuth, ""},
	{"node", "express-jwt", DepRoleAuth, ""},
	{"node", "express-session", DepRoleAuth, ""},
	{"node", "cookie-session", DepRoleAuth, ""},
	{"node", "iron-session", DepRoleAuth, ""},
	{"node", "@clerk/*", DepRoleAuth, ""},
	{"node", "@auth0/*", DepRoleAuth, ""},
	{"node", "auth0", DepRoleAuth, ""},
	{"node", "oidc-provider", DepRoleAuth, ""},
	{"node", "bcrypt", DepRoleCrypto, ""},
	{"node", "bcryptjs", DepRoleCrypto, ""},
	{"node", "argon2", DepRoleCrypto, ""},
	{"node", "@node-rs/bcrypt", DepRoleCrypto, ""},
	{"node", "@node-rs/argon2", DepRoleCrypto, ""},
	{"node", "crypto-js", DepRoleCrypto, ""},
	{"node", "node-forge", DepRoleCrypto, ""},
	{"node", "tweetnacl", DepRoleCrypto, ""},
	{"node", "libsodium-wrappers", DepRoleCrypto, ""},
	{"node", "sodium-native", DepRoleCrypto, ""},
	{"node", "jsrsasign", DepRoleCrypto, ""},
	{"node", "@noble/*", DepRoleCrypto, ""},
	{"node", "prisma", DepRoleORM, ""},
	{"node", "@prisma/client", DepRoleORM, ""},
	{"node", "sequelize", DepRoleORM, ""},
	{"node", "typeorm", DepRoleORM, ""},
	{"node", "mongoose", DepRoleORM, ""},
	{"node", "knex", DepRoleORM, ""},
	{"node", "kysely", DepRoleORM, ""},
	{"node", "drizzle-orm", DepRoleORM, ""},
	{"node", "@mikro-orm/core", DepRoleORM, ""},
	{"node", "objection", DepRoleORM, ""},
	{"node", "bookshelf", DepRoleORM, ""},
	{"node", "ejs", DepRoleTemplate, ""},
	{"node", "pug", DepRoleTemplate, ""},
	{"node", "handlebars", DepRoleTemplate, ""},
	{"node", "hbs", DepRoleTemplate, ""},
	{"node", "express-handlebars", DepRoleTemplate, ""},
	{"node", "mustache", DepRoleTemplate, ""},
	{"node", "nunjucks", DepRoleTemplate, ""},
	{"node", "liquidjs", DepRoleTemplate, ""},
	{"node", "eta", DepRoleTemplate, ""},
	{"node", "marko", DepRoleTemplate, ""},
	{"node", "axios", DepRoleHTTPClient, ""},
	{"node", "node-fetch", DepRoleHTTPClient, ""},
	{"node", "cross-fetch", DepRoleHTTPClient, ""},
	{"node", "isomorphic-fetch", DepRoleHTTPClient, ""},
	{"node", "got", DepRoleHTTPClient, ""},
	{"node", "undici", DepRoleHTTPClient, ""},
	{"node", "superagent", DepRoleHTTPClient, ""},
	{"node", "request", DepRoleHTTPClient, ""},
	{"node", "ky", DepRoleHTTPClient, ""},
	{"node", "needle", DepRoleHTTPClient, ""},
	{"node", "ofetch", DepRoleHTTPClient, ""},
	{"node", "bull", DepRoleQueue, ""},
	{"node", "bullmq", DepRoleQueue, ""},
	{"node", "@nestjs/bull", DepRoleQueue, ""},
	{"node", "@nestjs/bullmq", DepRoleQueue, ""},
	{"node", "bee-queue", DepRoleQueue, ""},
	{"node", "agenda", DepRoleQueue, ""},
	{"node", "kue", DepRoleQueue, ""},
	{"node", "pg-boss", DepRoleQueue, ""},
	{"node", "graphile-worker", DepRoleQueue, ""},
	{"node", "amqplib", DepRoleQueue, ""},
	{"node", "kafkajs", DepRoleQueue, ""},
	{"node", "@aws-sdk/client-sqs", DepRoleQueue, ""},
	{"node", "@google-cloud/pubsub", DepRoleQueue, ""},
	{"node", "openai", DepRoleLLMSDK, ""},
	{"node", "@anthropic-ai/sdk", DepRoleLLMSDK, ""},
	{"node", "@anthropic-ai/bedrock-sdk", DepRoleLLMSDK, ""},
	{"node", "@anthropic-ai/vertex-sdk", DepRoleLLMSDK, ""},
	{"node", "@google/generative-ai", DepRoleLLMSDK, ""},
	{"node", "@google/genai", DepRoleLLMSDK, ""},
	{"node", "@mistralai/mistralai", DepRoleLLMSDK, ""},
	{"node", "cohere-ai", DepRoleLLMSDK, ""},
	{"node", "groq-sdk", DepRoleLLMSDK, ""},
	{"node", "ollama", DepRoleLLMSDK, ""},
	{"node", "langchain", DepRoleLLMSDK, ""},
	{"node", "@langchain/*", DepRoleLLMSDK, ""},
	{"node", "llamaindex", DepRoleLLMSDK, ""},
	{"node", "ai", DepRoleLLMSDK, ""},
	{"node", "@ai-sdk/*", DepRoleLLMSDK, ""},
	{"node", "@huggingface/inference", DepRoleLLMSDK, ""},
	{"node", "@huggingface/transformers", DepRoleLLMSDK, ""},
	{"node", "@xenova/transformers", DepRoleLLMSDK, ""},
	{"node", "@aws-sdk/client-bedrock-runtime", DepRoleLLMSDK, ""},
	{"node", "@azure/openai", DepRoleLLMSDK, ""},
	{"node", "replicate", DepRoleLLMSDK, ""},
	{"node", "together-ai", DepRoleLLMSDK, ""},
	{"node", "@modelcontextprotocol/*", DepRoleMCPSDK, ""},
	{"node", "fastmcp", DepRoleMCPSDK, ""},
	{"node", "mcp-framework", DepRoleMCPSDK, ""},

	// ---- python ----
	{"python", "flask", DepRoleWebFramework, "flask"},
	{"python", "django", DepRoleWebFramework, "django"},
	{"python", "fastapi", DepRoleWebFramework, "fastapi"},
	{"python", "starlette", DepRoleWebFramework, "starlette"},
	{"python", "tornado", DepRoleWebFramework, "tornado"},
	{"python", "bottle", DepRoleWebFramework, "bottle"},
	{"python", "pyramid", DepRoleWebFramework, "pyramid"},
	{"python", "sanic", DepRoleWebFramework, "sanic"},
	{"python", "quart", DepRoleWebFramework, "quart"},
	{"python", "falcon", DepRoleWebFramework, "falcon"},
	{"python", "litestar", DepRoleWebFramework, "litestar"},
	{"python", "aiohttp", DepRoleWebFramework, ""},
	{"python", "cherrypy", DepRoleWebFramework, ""},
	{"python", "streamlit", DepRoleWebFramework, "streamlit"},
	{"python", "gradio", DepRoleWebFramework, "gradio"},
	{"python", "flask-login", DepRoleAuth, ""},
	{"python", "flask-security", DepRoleAuth, ""},
	{"python", "flask-security-too", DepRoleAuth, ""},
	{"python", "flask-jwt-extended", DepRoleAuth, ""},
	{"python", "flask-httpauth", DepRoleAuth, ""},
	{"python", "flask-session", DepRoleAuth, ""},
	{"python", "django-allauth", DepRoleAuth, ""},
	{"python", "django-oauth-toolkit", DepRoleAuth, ""},
	{"python", "djangorestframework-simplejwt", DepRoleAuth, ""},
	{"python", "django-otp", DepRoleAuth, ""},
	{"python", "mozilla-django-oidc", DepRoleAuth, ""},
	{"python", "social-auth-app-django", DepRoleAuth, ""},
	{"python", "fastapi-users", DepRoleAuth, ""},
	{"python", "authlib", DepRoleAuth, ""},
	{"python", "python-jose", DepRoleAuth, ""},
	{"python", "pyjwt", DepRoleAuth, ""},
	{"python", "oauthlib", DepRoleAuth, ""},
	{"python", "cryptography", DepRoleCrypto, ""},
	{"python", "pycryptodome", DepRoleCrypto, ""},
	{"python", "pycryptodomex", DepRoleCrypto, ""},
	{"python", "pynacl", DepRoleCrypto, ""},
	{"python", "passlib", DepRoleCrypto, ""},
	{"python", "bcrypt", DepRoleCrypto, ""},
	{"python", "argon2-cffi", DepRoleCrypto, ""},
	{"python", "pyopenssl", DepRoleCrypto, ""},
	{"python", "sqlalchemy", DepRoleORM, ""},
	{"python", "flask-sqlalchemy", DepRoleORM, ""},
	{"python", "sqlmodel", DepRoleORM, ""},
	{"python", "peewee", DepRoleORM, ""},
	{"python", "tortoise-orm", DepRoleORM, ""},
	{"python", "pony", DepRoleORM, ""},
	{"python", "mongoengine", DepRoleORM, ""},
	{"python", "beanie", DepRoleORM, ""},
	{"python", "jinja2", DepRoleTemplate, ""},
	{"python", "mako", DepRoleTemplate, ""},
	{"python", "chameleon", DepRoleTemplate, ""},
	{"python", "pystache", DepRoleTemplate, ""},
	{"python", "requests", DepRoleHTTPClient, ""},
	{"python", "httpx", DepRoleHTTPClient, ""},
	{"python", "aiohttp", DepRoleHTTPClient, ""},
	{"python", "urllib3", DepRoleHTTPClient, ""},
	{"python", "httplib2", DepRoleHTTPClient, ""},
	{"python", "treq", DepRoleHTTPClient, ""},
	{"python", "pycurl", DepRoleHTTPClient, ""},
	{"python", "celery", DepRoleQueue, ""},
	{"python", "rq", DepRoleQueue, ""},
	{"python", "dramatiq", DepRoleQueue, ""},
	{"python", "huey", DepRoleQueue, ""},
	{"python", "arq", DepRoleQueue, ""},
	{"python", "taskiq", DepRoleQueue, ""},
	{"python", "kombu", DepRoleQueue, ""},
	{"python", "pika", DepRoleQueue, ""},
	{"python", "aio-pika", DepRoleQueue, ""},
	{"python", "kafka-python", DepRoleQueue, ""},
	{"python", "confluent-kafka", DepRoleQueue, ""},
	{"python", "aiokafka", DepRoleQueue, ""},
	{"python", "openai", DepRoleLLMSDK, ""},
	{"python", "anthropic", DepRoleLLMSDK, ""},
	{"python", "langchain", DepRoleLLMSDK, ""},
	{"python", "langchain-*", DepRoleLLMSDK, ""},
	{"python", "langgraph", DepRoleLLMSDK, ""},
	{"python", "llama-index", DepRoleLLMSDK, ""},
	{"python", "llama-index-*", DepRoleLLMSDK, ""},
	{"python", "google-generativeai", DepRoleLLMSDK, ""},
	{"python", "google-genai", DepRoleLLMSDK, ""},
	{"python", "cohere", DepRoleLLMSDK, ""},
	{"python", "mistralai", DepRoleLLMSDK, ""},
	{"python", "ollama", DepRoleLLMSDK, ""},
	{"python", "litellm", DepRoleLLMSDK, ""},
	{"python", "transformers", DepRoleLLMSDK, ""},
	{"python", "huggingface-hub", DepRoleLLMSDK, ""},
	{"python", "groq", DepRoleLLMSDK, ""},
	{"python", "replicate", DepRoleLLMSDK, ""},
	{"python", "together", DepRoleLLMSDK, ""},
	{"python", "crewai", DepRoleLLMSDK, ""},
	{"python", "pyautogen", DepRoleLLMSDK, ""},
	{"python", "autogen-agentchat", DepRoleLLMSDK, ""},
	{"python", "dspy", DepRoleLLMSDK, ""},
	{"python", "dspy-ai", DepRoleLLMSDK, ""},
	{"python", "semantic-kernel", DepRoleLLMSDK, ""},
	{"python", "instructor", DepRoleLLMSDK, ""},
	{"python", "openai-agents", DepRoleLLMSDK, ""},
	{"python", "pydantic-ai", DepRoleLLMSDK, ""},
	{"python", "haystack-ai", DepRoleLLMSDK, ""},
	{"python", "mcp", DepRoleMCPSDK, ""},
	{"python", "fastmcp", DepRoleMCPSDK, ""},
	{"python", "fastapi-mcp", DepRoleMCPSDK, ""},
	{"python", "mcp-use", DepRoleMCPSDK, ""},

	// ---- ruby ----
	{"ruby", "rails", DepRoleWebFramework, "rails"},
	{"ruby", "sinatra", DepRoleWebFramework, "sinatra"},
	{"ruby", "hanami", DepRoleWebFramework, "hanami"},
	{"ruby", "grape", DepRoleWebFramework, "grape"},
	{"ruby", "padrino", DepRoleWebFramework, "padrino"},
	{"ruby", "roda", DepRoleWebFramework, "roda"},
	{"ruby", "devise", DepRoleAuth, ""},
	{"ruby", "omniauth", DepRoleAuth, ""},
	{"ruby", "omniauth-*", DepRoleAuth, ""},
	{"ruby", "doorkeeper", DepRoleAuth, ""},
	{"ruby", "warden", DepRoleAuth, ""},
	{"ruby", "jwt", DepRoleAuth, ""},
	{"ruby", "rodauth", DepRoleAuth, ""},
	{"ruby", "sorcery", DepRoleAuth, ""},
	{"ruby", "clearance", DepRoleAuth, ""},
	{"ruby", "authlogic", DepRoleAuth, ""},
	{"ruby", "bcrypt", DepRoleCrypto, ""},
	{"ruby", "argon2", DepRoleCrypto, ""},
	{"ruby", "rbnacl", DepRoleCrypto, ""},
	{"ruby", "openssl", DepRoleCrypto, ""},
	{"ruby", "activerecord", DepRoleORM, ""},
	{"ruby", "sequel", DepRoleORM, ""},
	{"ruby", "mongoid", DepRoleORM, ""},
	{"ruby", "rom", DepRoleORM, ""},
	{"ruby", "erubi", DepRoleTemplate, ""},
	{"ruby", "haml", DepRoleTemplate, ""},
	{"ruby", "slim", DepRoleTemplate, ""},
	{"ruby", "liquid", DepRoleTemplate, ""},
	{"ruby", "mustache", DepRoleTemplate, ""},
	{"ruby", "tilt", DepRoleTemplate, ""},
	{"ruby", "faraday", DepRoleHTTPClient, ""},
	{"ruby", "httparty", DepRoleHTTPClient, ""},
	{"ruby", "rest-client", DepRoleHTTPClient, ""},
	{"ruby", "typhoeus", DepRoleHTTPClient, ""},
	{"ruby", "excon", DepRoleHTTPClient, ""},
	{"ruby", "sidekiq", DepRoleQueue, ""},
	{"ruby", "resque", DepRoleQueue, ""},
	{"ruby", "delayed_job", DepRoleQueue, ""},
	{"ruby", "delayed_job_active_record", DepRoleQueue, ""},
	{"ruby", "good_job", DepRoleQueue, ""},
	{"ruby", "que", DepRoleQueue, ""},
	{"ruby", "shoryuken", DepRoleQueue, ""},
	{"ruby", "bunny", DepRoleQueue, ""},
	{"ruby", "sneakers", DepRoleQueue, ""},
	{"ruby", "karafka", DepRoleQueue, ""},
	{"ruby", "ruby-kafka", DepRoleQueue, ""},
	{"ruby", "rdkafka", DepRoleQueue, ""},
	{"ruby", "ruby-openai", DepRoleLLMSDK, ""},
	{"ruby", "openai", DepRoleLLMSDK, ""},
	{"ruby", "anthropic", DepRoleLLMSDK, ""},
	{"ruby", "ruby-anthropic", DepRoleLLMSDK, ""},
	{"ruby", "langchainrb", DepRoleLLMSDK, ""},
	{"ruby", "ruby_llm", DepRoleLLMSDK, ""},
	{"ruby", "mcp", DepRoleMCPSDK, ""},
	{"ruby", "fast-mcp", DepRoleMCPSDK, ""},

	// ---- php ----
	{"php", "laravel/framework", DepRoleWebFramework, "laravel"},
	{"php", "symfony/framework-bundle", DepRoleWebFramework, "symfony"},
	{"php", "symfony/symfony", DepRoleWebFramework, "symfony"},
	{"php", "slim/slim", DepRoleWebFramework, "slim"},
	{"php", "cakephp/cakephp", DepRoleWebFramework, "cakephp"},
	{"php", "yiisoft/yii2", DepRoleWebFramework, "yii"},
	{"php", "codeigniter4/framework", DepRoleWebFramework, "codeigniter"},
	{"php", "laravel/sanctum", DepRoleAuth, ""},
	{"php", "laravel/passport", DepRoleAuth, ""},
	{"php", "laravel/breeze", DepRoleAuth, ""},
	{"php", "laravel/jetstream", DepRoleAuth, ""},
	{"php", "laravel/fortify", DepRoleAuth, ""},
	{"php", "laravel/socialite", DepRoleAuth, ""},
	{"php", "tymon/jwt-auth", DepRoleAuth, ""},
	{"php", "firebase/php-jwt", DepRoleAuth, ""},
	{"php", "lcobucci/jwt", DepRoleAuth, ""},
	{"php", "league/oauth2-server", DepRoleAuth, ""},
	{"php", "league/oauth2-client", DepRoleAuth, ""},
	{"php", "symfony/security-bundle", DepRoleAuth, ""},
	{"php", "defuse/php-encryption", DepRoleCrypto, ""},
	{"php", "paragonie/halite", DepRoleCrypto, ""},
	{"php", "paragonie/sodium_compat", DepRoleCrypto, ""},
	{"php", "phpseclib/phpseclib", DepRoleCrypto, ""},
	{"php", "doctrine/orm", DepRoleORM, ""},
	{"php", "illuminate/database", DepRoleORM, ""},
	{"php", "cycle/orm", DepRoleORM, ""},
	{"php", "propel/propel", DepRoleORM, ""},
	{"php", "twig/twig", DepRoleTemplate, ""},
	{"php", "symfony/twig-bundle", DepRoleTemplate, ""},
	{"php", "smarty/smarty", DepRoleTemplate, ""},
	{"php", "mustache/mustache", DepRoleTemplate, ""},
	{"php", "league/plates", DepRoleTemplate, ""},
	{"php", "guzzlehttp/guzzle", DepRoleHTTPClient, ""},
	{"php", "symfony/http-client", DepRoleHTTPClient, ""},
	{"php", "php-http/*", DepRoleHTTPClient, ""},
	{"php", "php-amqplib/php-amqplib", DepRoleQueue, ""},
	{"php", "laravel/horizon", DepRoleQueue, ""},
	{"php", "enqueue/enqueue", DepRoleQueue, ""},
	{"php", "symfony/messenger", DepRoleQueue, ""},
	{"php", "bernard/bernard", DepRoleQueue, ""},
	{"php", "openai-php/client", DepRoleLLMSDK, ""},
	{"php", "openai-php/laravel", DepRoleLLMSDK, ""},
	{"php", "anthropic-ai/sdk", DepRoleLLMSDK, ""},
	{"php", "theodo-group/llphant", DepRoleLLMSDK, ""},
	{"php", "google-gemini-php/client", DepRoleLLMSDK, ""},
	{"php", "modelcontextprotocol/php-sdk", DepRoleMCPSDK, ""},
	{"php", "php-mcp/*", DepRoleMCPSDK, ""},

	// ---- go (module paths; a /vN major suffix is ignored) ----
	{"go", "github.com/gin-gonic/gin", DepRoleWebFramework, "gin"},
	{"go", "github.com/labstack/echo", DepRoleWebFramework, "echo"},
	{"go", "github.com/gofiber/fiber", DepRoleWebFramework, "fiber"},
	{"go", "github.com/go-chi/chi", DepRoleWebFramework, "chi"},
	{"go", "github.com/gorilla/mux", DepRoleWebFramework, "gorilla"},
	{"go", "github.com/beego/beego", DepRoleWebFramework, "beego"},
	{"go", "github.com/astaxie/beego", DepRoleWebFramework, "beego"},
	{"go", "github.com/gobuffalo/buffalo", DepRoleWebFramework, "buffalo"},
	{"go", "github.com/revel/revel", DepRoleWebFramework, "revel"},
	{"go", "github.com/danielgtaylor/huma", DepRoleWebFramework, ""},
	{"go", "github.com/valyala/fasthttp", DepRoleWebFramework, ""},
	{"go", "github.com/golang-jwt/jwt", DepRoleAuth, ""},
	{"go", "github.com/dgrijalva/jwt-go", DepRoleAuth, ""},
	{"go", "github.com/lestrrat-go/jwx", DepRoleAuth, ""},
	{"go", "github.com/gorilla/sessions", DepRoleAuth, ""},
	{"go", "github.com/gin-contrib/sessions", DepRoleAuth, ""},
	{"go", "github.com/alexedwards/scs", DepRoleAuth, ""},
	{"go", "golang.org/x/oauth2", DepRoleAuth, ""},
	{"go", "github.com/coreos/go-oidc", DepRoleAuth, ""},
	{"go", "github.com/zitadel/oidc", DepRoleAuth, ""},
	{"go", "github.com/markbates/goth", DepRoleAuth, ""},
	{"go", "github.com/casbin/casbin", DepRoleAuth, ""},
	{"go", "github.com/ory/fosite", DepRoleAuth, ""},
	{"go", "github.com/go-webauthn/webauthn", DepRoleAuth, ""},
	{"go", "golang.org/x/crypto", DepRoleCrypto, ""},
	{"go", "github.com/cloudflare/circl", DepRoleCrypto, ""},
	{"go", "filippo.io/age", DepRoleCrypto, ""},
	{"go", "github.com/protonmail/go-crypto", DepRoleCrypto, ""},
	{"go", "github.com/alexedwards/argon2id", DepRoleCrypto, ""},
	{"go", "gorm.io/gorm", DepRoleORM, ""},
	{"go", "github.com/jinzhu/gorm", DepRoleORM, ""},
	{"go", "entgo.io/ent", DepRoleORM, ""},
	{"go", "github.com/jmoiron/sqlx", DepRoleORM, ""},
	{"go", "github.com/uptrace/bun", DepRoleORM, ""},
	{"go", "github.com/go-pg/pg", DepRoleORM, ""},
	{"go", "github.com/volatiletech/sqlboiler", DepRoleORM, ""},
	{"go", "github.com/upper/db", DepRoleORM, ""},
	{"go", "github.com/doug-martin/goqu", DepRoleORM, ""},
	{"go", "github.com/a-h/templ", DepRoleTemplate, ""},
	{"go", "github.com/flosch/pongo2", DepRoleTemplate, ""},
	{"go", "github.com/aymerick/raymond", DepRoleTemplate, ""},
	{"go", "github.com/cbroglie/mustache", DepRoleTemplate, ""},
	{"go", "github.com/go-resty/resty", DepRoleHTTPClient, ""},
	{"go", "github.com/hashicorp/go-retryablehttp", DepRoleHTTPClient, ""},
	{"go", "github.com/imroc/req", DepRoleHTTPClient, ""},
	{"go", "github.com/carlmjohnson/requests", DepRoleHTTPClient, ""},
	{"go", "github.com/hibiken/asynq", DepRoleQueue, ""},
	{"go", "github.com/segmentio/kafka-go", DepRoleQueue, ""},
	{"go", "github.com/rabbitmq/amqp091-go", DepRoleQueue, ""},
	{"go", "github.com/streadway/amqp", DepRoleQueue, ""},
	{"go", "github.com/nats-io/nats.go", DepRoleQueue, ""},
	{"go", "github.com/ibm/sarama", DepRoleQueue, ""},
	{"go", "github.com/shopify/sarama", DepRoleQueue, ""},
	{"go", "github.com/confluentinc/confluent-kafka-go", DepRoleQueue, ""},
	{"go", "github.com/riverqueue/river", DepRoleQueue, ""},
	{"go", "github.com/nsqio/go-nsq", DepRoleQueue, ""},
	{"go", "cloud.google.com/go/pubsub", DepRoleQueue, ""},
	{"go", "github.com/sashabaranov/go-openai", DepRoleLLMSDK, ""},
	{"go", "github.com/openai/openai-go", DepRoleLLMSDK, ""},
	{"go", "github.com/anthropics/anthropic-sdk-go", DepRoleLLMSDK, ""},
	{"go", "github.com/liushuangls/go-anthropic", DepRoleLLMSDK, ""},
	{"go", "github.com/tmc/langchaingo", DepRoleLLMSDK, ""},
	{"go", "github.com/google/generative-ai-go", DepRoleLLMSDK, ""},
	{"go", "google.golang.org/genai", DepRoleLLMSDK, ""},
	{"go", "github.com/cohere-ai/cohere-go", DepRoleLLMSDK, ""},
	{"go", "github.com/firebase/genkit/go", DepRoleLLMSDK, ""},
	{"go", "github.com/cloudwego/eino", DepRoleLLMSDK, ""},
	{"go", "github.com/mark3labs/mcp-go", DepRoleMCPSDK, ""},
	{"go", "github.com/modelcontextprotocol/go-sdk", DepRoleMCPSDK, ""},
	{"go", "github.com/metoro-io/mcp-golang", DepRoleMCPSDK, ""},

	// ---- rust ----
	{"rust", "actix-web", DepRoleWebFramework, "actix"},
	{"rust", "axum", DepRoleWebFramework, "axum"},
	{"rust", "rocket", DepRoleWebFramework, "rocket"},
	{"rust", "warp", DepRoleWebFramework, "warp"},
	{"rust", "poem", DepRoleWebFramework, "poem"},
	{"rust", "salvo", DepRoleWebFramework, ""},
	{"rust", "tide", DepRoleWebFramework, ""},
	{"rust", "jsonwebtoken", DepRoleAuth, ""},
	{"rust", "oauth2", DepRoleAuth, ""},
	{"rust", "openidconnect", DepRoleAuth, ""},
	{"rust", "axum-login", DepRoleAuth, ""},
	{"rust", "tower-sessions", DepRoleAuth, ""},
	{"rust", "actix-session", DepRoleAuth, ""},
	{"rust", "actix-identity", DepRoleAuth, ""},
	{"rust", "ring", DepRoleCrypto, ""},
	{"rust", "rustls", DepRoleCrypto, ""},
	{"rust", "openssl", DepRoleCrypto, ""},
	{"rust", "argon2", DepRoleCrypto, ""},
	{"rust", "bcrypt", DepRoleCrypto, ""},
	{"rust", "aes-gcm", DepRoleCrypto, ""},
	{"rust", "chacha20poly1305", DepRoleCrypto, ""},
	{"rust", "ed25519-dalek", DepRoleCrypto, ""},
	{"rust", "diesel", DepRoleORM, ""},
	{"rust", "sea-orm", DepRoleORM, ""},
	{"rust", "sqlx", DepRoleORM, ""},
	{"rust", "tera", DepRoleTemplate, ""},
	{"rust", "askama", DepRoleTemplate, ""},
	{"rust", "handlebars", DepRoleTemplate, ""},
	{"rust", "maud", DepRoleTemplate, ""},
	{"rust", "minijinja", DepRoleTemplate, ""},
	{"rust", "reqwest", DepRoleHTTPClient, ""},
	{"rust", "ureq", DepRoleHTTPClient, ""},
	{"rust", "surf", DepRoleHTTPClient, ""},
	{"rust", "isahc", DepRoleHTTPClient, ""},
	{"rust", "lapin", DepRoleQueue, ""},
	{"rust", "rdkafka", DepRoleQueue, ""},
	{"rust", "apalis", DepRoleQueue, ""},
	{"rust", "async-openai", DepRoleLLMSDK, ""},
	{"rust", "ollama-rs", DepRoleLLMSDK, ""},
	{"rust", "rig-core", DepRoleLLMSDK, ""},
	{"rust", "genai", DepRoleLLMSDK, ""},
	{"rust", "llm-chain", DepRoleLLMSDK, ""},
	{"rust", "rmcp", DepRoleMCPSDK, ""},
	{"rust", "rust-mcp-sdk", DepRoleMCPSDK, ""},

	// ---- java (artifact ids) ----
	{"java", "spring-boot-starter-web", DepRoleWebFramework, "spring"},
	{"java", "spring-boot-starter-webflux", DepRoleWebFramework, "spring"},
	{"java", "spring-webmvc", DepRoleWebFramework, "spring"},
	{"java", "quarkus-rest*", DepRoleWebFramework, "quarkus"},
	{"java", "quarkus-resteasy*", DepRoleWebFramework, "quarkus"},
	{"java", "micronaut-http-server-netty", DepRoleWebFramework, "micronaut"},
	{"java", "javalin", DepRoleWebFramework, "javalin"},
	{"java", "dropwizard-core", DepRoleWebFramework, "dropwizard"},
	{"java", "vertx-web", DepRoleWebFramework, "vertx"},
	{"java", "spring-boot-starter-security", DepRoleAuth, ""},
	{"java", "spring-security-core", DepRoleAuth, ""},
	{"java", "spring-security-web", DepRoleAuth, ""},
	{"java", "spring-boot-starter-oauth2-client", DepRoleAuth, ""},
	{"java", "spring-boot-starter-oauth2-resource-server", DepRoleAuth, ""},
	{"java", "java-jwt", DepRoleAuth, ""},
	{"java", "jjwt-api", DepRoleAuth, ""},
	{"java", "nimbus-jose-jwt", DepRoleAuth, ""},
	{"java", "shiro-core", DepRoleAuth, ""},
	{"java", "pac4j-core", DepRoleAuth, ""},
	{"java", "bcprov-*", DepRoleCrypto, ""},
	{"java", "bcpkix-*", DepRoleCrypto, ""},
	{"java", "spring-security-crypto", DepRoleCrypto, ""},
	{"java", "jasypt", DepRoleCrypto, ""},
	{"java", "tink", DepRoleCrypto, ""},
	{"java", "hibernate-core", DepRoleORM, ""},
	{"java", "spring-boot-starter-data-jpa", DepRoleORM, ""},
	{"java", "spring-data-jpa", DepRoleORM, ""},
	{"java", "mybatis", DepRoleORM, ""},
	{"java", "mybatis-spring-boot-starter", DepRoleORM, ""},
	{"java", "jooq", DepRoleORM, ""},
	{"java", "spring-boot-starter-thymeleaf", DepRoleTemplate, ""},
	{"java", "thymeleaf", DepRoleTemplate, ""},
	{"java", "spring-boot-starter-freemarker", DepRoleTemplate, ""},
	{"java", "freemarker", DepRoleTemplate, ""},
	{"java", "spring-boot-starter-mustache", DepRoleTemplate, ""},
	{"java", "pebble", DepRoleTemplate, ""},
	{"java", "velocity-engine-core", DepRoleTemplate, ""},
	{"java", "okhttp", DepRoleHTTPClient, ""},
	{"java", "httpclient", DepRoleHTTPClient, ""},
	{"java", "httpclient5", DepRoleHTTPClient, ""},
	{"java", "feign-core", DepRoleHTTPClient, ""},
	{"java", "retrofit", DepRoleHTTPClient, ""},
	{"java", "unirest-java", DepRoleHTTPClient, ""},
	{"java", "spring-kafka", DepRoleQueue, ""},
	{"java", "kafka-clients", DepRoleQueue, ""},
	{"java", "spring-boot-starter-amqp", DepRoleQueue, ""},
	{"java", "amqp-client", DepRoleQueue, ""},
	{"java", "spring-rabbit", DepRoleQueue, ""},
	{"java", "spring-boot-starter-activemq", DepRoleQueue, ""},
	{"java", "activemq-client", DepRoleQueue, ""},
	{"java", "spring-jms", DepRoleQueue, ""},
	{"java", "spring-cloud-stream", DepRoleQueue, ""},
	{"java", "spring-ai-*", DepRoleLLMSDK, ""},
	{"java", "langchain4j", DepRoleLLMSDK, ""},
	{"java", "langchain4j-*", DepRoleLLMSDK, ""},
	{"java", "openai-java", DepRoleLLMSDK, ""},
	{"java", "anthropic-java", DepRoleLLMSDK, ""},
	{"java", "mcp", DepRoleMCPSDK, ""},
	{"java", "mcp-core", DepRoleMCPSDK, ""},
	{"java", "mcp-spring-*", DepRoleMCPSDK, ""},
	{"java", "spring-ai-starter-mcp-*", DepRoleMCPSDK, ""},
}

// depRoleIndex is the table split for lookup: exact names by ecosystem, and
// the prefix rows by ecosystem.
type depRoleIndex struct {
	exact  map[string][]depRoleRule
	prefix map[string][]depRoleRule
}

var depRoleIdx = buildDepRoleIndex()

func buildDepRoleIndex() depRoleIndex {
	idx := depRoleIndex{exact: map[string][]depRoleRule{}, prefix: map[string][]depRoleRule{}}
	for _, r := range depRoleRules {
		key := strings.ToLower(r.match)
		if strings.HasSuffix(key, "*") {
			r.match = strings.TrimSuffix(key, "*")
			idx.prefix[r.lang] = append(idx.prefix[r.lang], r)
			continue
		}
		r.match = key
		idx.exact[r.lang+"\x00"+key] = append(idx.exact[r.lang+"\x00"+key], r)
	}
	return idx
}

// projFrameworkIDs is the closed framework list: the framework ids of the table,
// in the order they first appear.
var projFrameworkIDs = func() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range depRoleRules {
		if r.framework != "" && !seen[r.framework] {
			seen[r.framework] = true
			out = append(out, r.framework)
		}
	}
	return out
}()

// ProjectFrameworkIDs returns the closed framework ids ProjectFacts.Frameworks draws
// from, in table order.
func ProjectFrameworkIDs() []string { return append([]string(nil), projFrameworkIDs...) }

// depNormalize returns the form of a dependency name the table is matched
// against: lower case; Python names follow PEP 503 (runs of - _ . become -),
// Rust crate names treat _ as -, a Go module path loses a /vN major suffix.
func depNormalize(lang, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch lang {
	case "python":
		var b strings.Builder
		dash := false
		for i := 0; i < len(name); i++ {
			ch := name[i]
			if ch == '-' || ch == '_' || ch == '.' {
				dash = true
				continue
			}
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteByte(ch)
		}
		return b.String()
	case "rust":
		return strings.ReplaceAll(name, "_", "-")
	case "go":
		return depTrimMajor(name)
	}
	return name
}

// depTrimMajor drops a trailing /v2, /v3, ... from a Go module path.
func depTrimMajor(p string) string {
	i := strings.LastIndex(p, "/v")
	if i < 0 || i+2 >= len(p) {
		return p
	}
	for _, ch := range p[i+2:] {
		if ch < '0' || ch > '9' {
			return p
		}
	}
	return p[:i]
}

// depRolesOf returns the roles and framework ids a dependency (already
// normalised) has in ecosystem lang, each once, in table order.
func depRolesOf(lang, name string) (roles, frameworks []string) {
	var hits []depRoleRule
	hits = append(hits, depRoleIdx.exact[lang+"\x00"+name]...)
	for _, r := range depRoleIdx.prefix[lang] {
		if strings.HasPrefix(name, r.match) {
			hits = append(hits, r)
		}
	}
	for _, r := range hits {
		if r.role != "" && !strSliceHas(roles, r.role) {
			roles = append(roles, r.role)
		}
		if r.framework != "" && !strSliceHas(frameworks, r.framework) {
			frameworks = append(frameworks, r.framework)
		}
	}
	return roles, frameworks
}

// strSliceHas reports whether s is in list.
func strSliceHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
