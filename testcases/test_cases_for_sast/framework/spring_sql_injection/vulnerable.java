@Query("select u from User u where u.name = '" + name + "'")
List<User> findByName(String name);  // DANGEROUS
