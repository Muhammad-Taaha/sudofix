function displayUser() {
    let user = document.getElementById("user").value;
    document.getElementById("output").innerHTML = user;  // DANGEROUS
}
