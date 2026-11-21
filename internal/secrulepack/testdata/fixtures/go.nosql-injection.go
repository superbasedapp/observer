package web

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var users *mongo.Collection

type loginForm struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func search(w http.ResponseWriter, r *http.Request) {
	var filter bson.M
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		return
	}
	// ruleid: go.nosql-injection
	cur, _ := users.Find(r.Context(), filter)
	_ = cur
}

func login(w http.ResponseWriter, r *http.Request) {
	var form loginForm
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		return
	}
	// ok: go.nosql-injection
	res := users.FindOne(r.Context(), bson.M{"email": form.Email, "password": form.Password})
	// ok: go.nosql-injection
	byName := users.FindOne(r.Context(), bson.M{"name": r.FormValue("name")})
	_, _ = res, byName
}

func ginSearch(c *gin.Context) {
	body := map[string]interface{}{}
	if err := c.ShouldBindJSON(&body); err != nil {
		return
	}
	// ruleid: go.nosql-injection
	n, _ := users.CountDocuments(c, bson.M{"owner": body["owner"]})
	_ = n
}

// The program's own values, not request input.
func byFilter(r *http.Request, filter bson.M) {
	// ok: go.nosql-injection
	cur, _ := users.Find(r.Context(), filter)
	_ = cur
}
