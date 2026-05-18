@GetMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public String adminPanel() {
    return "admin";
}
