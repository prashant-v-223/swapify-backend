const authRole = (roles) => {
  return (req, res, next) => {
    try {
      const userRole = req.user.role; 
      console.log(userRole);
      // Assuming the authenticated user's role is available in the `role` property
      if (roles.includes(userRole)) {
        next(); // Allow access if the user's role matches one of the permitted roles
      }
      throw new Error("Unauthorized"); // Deny access if the user's role does not match
    } catch (error) {
      console.log(error);
      res.status(403).send("Unauthorized"); // Deny access if the user's role does not match
    }
  };
};

module.exports = authRole;
