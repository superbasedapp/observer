package web

import (
	"context"
	"encoding/json"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var orders *mongo.Collection

// Cross-function taint in one file (--taint-intrafile): the decoded body
// is handed to a helper that queries with it.
func findOrders(ctx context.Context, filter bson.M) {
	// ruleid: go.nosql-injection
	cur, _ := orders.Find(ctx, filter)
	_ = cur
}

func search(w http.ResponseWriter, r *http.Request) {
	var filter bson.M
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		return
	}
	findOrders(r.Context(), filter)
}

func requestedFilter(r *http.Request) bson.M {
	var filter bson.M
	_ = json.NewDecoder(r.Body).Decode(&filter)
	return filter
}

func count(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.nosql-injection
	n, _ := orders.CountDocuments(r.Context(), requestedFilter(r))
	_ = n
}

// The rule has no sanitizer: this helper ignores its input and builds a
// fixed filter, so no operator object reaches the query.
func ownerFilter(body bson.M) bson.M {
	return bson.M{"owner": "self"}
}

func owned(w http.ResponseWriter, r *http.Request) {
	var body bson.M
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return
	}
	// ok: go.nosql-injection
	n, _ := orders.CountDocuments(r.Context(), ownerFilter(body))
	_ = n
}
