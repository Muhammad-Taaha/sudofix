func login(c *gin.Context) {
    user := authenticate(c.PostForm("user"))
    session.Regenerate()   // SAFE
    session.Set("user", user)
    c.Redirect(302, "/dashboard")
}
