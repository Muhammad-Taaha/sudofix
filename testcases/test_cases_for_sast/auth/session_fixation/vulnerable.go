// Gin framework
func login(c *gin.Context) {
    user := authenticate(c.PostForm("user"))
    session.Set("user", user)   // DANGEROUS (no regeneration)
    c.Redirect(302, "/dashboard")
}
