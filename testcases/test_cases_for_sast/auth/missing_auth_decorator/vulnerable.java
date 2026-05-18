@GetMapping("/admin")
public String adminPanel() {   // DANGEROUS (no @PreAuthorize)
    return "admin";
}
