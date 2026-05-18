@PostMapping("/login")
public String login(HttpServletRequest request) {
    User user = authService.authenticate(request.getParameter("user"));
    request.changeSessionId();   // SAFE
    request.getSession().setAttribute("user", user);
    return "redirect:/dashboard";
}
