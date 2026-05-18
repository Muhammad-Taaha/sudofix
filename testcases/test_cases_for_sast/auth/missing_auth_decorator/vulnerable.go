// Gin route without auth middleware
r.GET("/admin", func(c *gin.Context) {
    c.String(200, "admin")   // DANGEROUS
})
