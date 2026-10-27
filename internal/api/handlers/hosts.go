package handlers

import (
	"net/http"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// ListDockerHosts returns all configured Docker hosts with connectivity status
func ListDockerHosts(multiHost *docker.MultiHostClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		hosts := multiHost.ListHosts()

		type HostStatus struct {
			docker.HostInfo
			Connected bool   `json:"connected"`
			Error     string `json:"error,omitempty"`
			IsDefault bool   `json:"is_default"`
		}

		defaultID := multiHost.DefaultHostID()
		results := make([]HostStatus, 0, len(hosts))

		for _, h := range hosts {
			hs := HostStatus{
				HostInfo:  h,
				IsDefault: h.ID == defaultID,
			}

			client, err := multiHost.GetClient(h.ID)
			if err != nil {
				hs.Error = err.Error()
			} else if err := client.Ping(); err != nil {
				hs.Error = err.Error()
			} else {
				hs.Connected = true
			}

			results = append(results, hs)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    results,
		})
	}
}

// RegisterLAPIInstanceRequest is the payload for registering a new CrowdSec LAPI instance at runtime.
type RegisterLAPIInstanceRequest struct {
	ID         string `json:"id"`
	LAPIURL    string `json:"lapi_url"`
	ConfigFile string `json:"config_file"`
}

// RegisterLAPIInstanceHandler dynamically registers or updates a CrowdSec LAPI instance.
func RegisterLAPIInstanceHandler(multiHost *docker.MultiHostClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterLAPIInstanceRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid LAPI instance payload: " + err.Error(),
			})
			return
		}
		if req.ID == "" || req.LAPIURL == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Both id and lapi_url are required",
			})
			return
		}
		multiHost.RegisterLAPIInstance(req.ID, req.LAPIURL, req.ConfigFile)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "LAPI instance registered",
			Data:    req,
		})
	}
}

// RemoveLAPIInstanceHandler removes a dynamically registered CrowdSec LAPI instance.
func RemoveLAPIInstanceHandler(multiHost *docker.MultiHostClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Instance ID is required",
			})
			return
		}
		if err := multiHost.RemoveLAPIInstance(id); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "LAPI instance removed",
		})
	}
}
