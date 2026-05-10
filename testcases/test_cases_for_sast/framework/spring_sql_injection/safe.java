@Query("select u from User u where u.name = :name")
List<User> findByName(@Param("name") String name);
