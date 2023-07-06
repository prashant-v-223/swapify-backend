// Middleware function to authenticate the admin user
function authenticateAdmin(req, res, next) {
  console.log(req.user && req.user.isAdmin);
  // Check if the user is authenticated and has admin privileges
  if (req.user && req.user.isAdmin) {
    // User is authenticated and has admin privileges, allow access to the route
    next();
  } else {
    // User is not authenticated or doesn't have admin privileges, return an error response
    res.status(401).json({ message: "Unauthorized" });
  }
}


module.exports = authenticateAdmin;