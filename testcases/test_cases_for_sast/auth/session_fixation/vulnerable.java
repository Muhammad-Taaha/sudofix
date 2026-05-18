@PostMapping("/login")
public String login(HttpServletRequest request) {
    User user = authService.authenticate(request.getParameter("user"));
    request.getSession().setAttribute("user", user);   // DANGEROUS
    return "redirect:/dashboard";
}
