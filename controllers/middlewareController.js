const jwt = require('jsonwebtoken');

const middlewareController = {
    // VERIFY TOKEN
    verifyToken: (req, res, next) => {
        const token = req.headers.token;
        if (token) {
            const accessToken = token.split(' ')[1]; // Access token: "Bearer ..."
            jwt.verify(accessToken, process.env.JWT_ACCESS_KEY, (err, user) => {
                if (err) {
                    return res.status(403).json('Token is invalid!'); // Forbidden
                }

                req.user = user;
                next();
            });
        } else {
            return res.status(401).json("You're not authenticated!");
        }
    },
    // VERIFY TOKEN AND ADMIN AUTH
    verifyTokenAndAdminAuth: (req, res, next) => {
        middlewareController.verifyToken(req, res, () => {
            if (req.user.id === req.params.id || req.user.role === 'admin') {
                next();
            } else {
                return res
                    .status(403)
                    .json("You're not allowed to delete other!");
            }
        });
    }
};

module.exports = middlewareController;
