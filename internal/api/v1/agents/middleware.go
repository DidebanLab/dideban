package agents

import (
	"strconv"
	"strings"

	"dideban/internal/api/types"
	"dideban/internal/storage"

	"github.com/gin-gonic/gin"
)

// AgentAuthMiddleware validates agent authentication via Bearer token.
func (h *Handler) AgentAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			types.AbortWithError(c, types.AuthorizationError("missing authorization header"))
			return
		}

		// Expect: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			types.AbortWithError(c, types.AuthorizationError("invalid authorization format"))
			return
		}

		token := parts[1]

		// Extract agent ID from URL path
		idStr := c.Param("id")
		agentID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			types.AbortWithError(c, types.ValidationError("invalid agent ID"))
			return
		}

		// Validate token against database
		var count int64
		if err := h.storage.DB().
			Model(&storage.Agent{}).
			Where("id = ? AND auth_token = ? AND enabled = ?", agentID, token, true).
			Count(&count).Error; err != nil {
			types.AbortWithError(c, types.InternalError("failed to validate agent token", err))
			return
		}

		if count == 0 {
			types.AbortWithError(c, types.AuthorizationError("invalid agent token"))
			return
		}

		c.Next()
	}
}
