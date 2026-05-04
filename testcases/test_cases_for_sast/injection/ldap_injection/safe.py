import ldap

def safe():
    user_filter = input("Enter filter: ")
    conn = ldap.initialize("ldap://localhost")
    safe_filter = ldap.filter.escape_filter_chars(user_filter)
    conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, f"(uid={safe_filter})")  # SAFE
