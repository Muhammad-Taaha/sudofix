r.GET("/admin", AuthRequired(), func(c *gin.Context) {
    c.String(200, "admin")
})
