// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func getRouter() *gin.Engine {
	engine := gin.Default()

	engine.GET("/api/v1/topology", GetTopology)

	return engine
}

func New(endpoint string) *http.Server {
	router := getRouter()
	return &http.Server{
		Addr:    endpoint,
		Handler: router,
	}
}
