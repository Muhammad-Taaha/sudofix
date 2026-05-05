import ldap
def vulnerable():
    user_filter = input("Enter filter: ")
    conn = ldap.initialize("ldap://localhost")
    conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, user_filter)  # DANGEROUS
