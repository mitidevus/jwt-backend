const bcrypt = require('bcrypt');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

let refreshTokens = []; // Example for Redis, used to cache refresh token
const authController = {
    // REGISTER
    registerUser: async (req, res) => {
        try {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);

            // Create new user
            const newUser = new User({
                username: req.body.username,
                email: req.body.email,
                password: hashedPassword
            });

            // Save to DB
            const user = await newUser.save();
            res.status(200).json(user);
        } catch (err) {
            res.status(500).json(err);
        }
    },
    // GENERATE ACCESS TOKEN
    generateAccessToken: (user) => {
        return jwt.sign(
            {
                id: user.id,
                role: user.role
            },
            process.env.JWT_ACCESS_KEY,
            {
                expiresIn: '180s'
            }
        );
    },
    // GENERATE REFRESH TOKEN
    generateRefreshToken: (user) => {
        return jwt.sign(
            {
                id: user.id,
                role: user.role
            },
            process.env.JWT_REFRESH_KEY,
            {
                expiresIn: '3d'
            }
        );
    },
    // LOGIN
    loginUser: async (req, res) => {
        try {
            const user = await User.findOne({ username: req.body.username });

            if (!user) {
                return res.status(404).json('Wrong username!');
            }

            const validPassword = await bcrypt.compare(
                req.body.password,
                user.password
            );

            if (!validPassword) {
                return res.status(404).json('Wrong password!');
            }

            if (user && validPassword) {
                const accessToken = authController.generateAccessToken(user);
                const refreshToken = authController.generateRefreshToken(user);

                refreshTokens.push(refreshToken);

                // Store refresh token to cookies
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: false, // When deploying, set to true
                    path: '/', // Don't require
                    sameSite: 'strict'
                });

                const { password, ...others } = user._doc;

                res.status(200).json({ ...others, accessToken });
            }
        } catch (err) {
            res.status(500).json(err);
        }
    },
    requestRefreshToken: async (req, res) => {
        // Take refresh token from user
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json("You're not authenticated!");
        }

        if (!refreshTokens.includes(refreshToken)) {
            return res.status(403).json('Refresh token is invalid!');
        }

        jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
            if (err) {
                console.log(err);
            }

            // Filter to get others refresh token and remove current refresh token
            refreshTokens = refreshTokens.filter(
                (token) => token !== refreshToken
            );

            // Create new access token and refresh token
            const newAccessToken = authController.generateAccessToken(user);
            const newRefreshToken = authController.generateRefreshToken(user);

            // Add new refresh token
            refreshTokens.push(newRefreshToken);

            // Store new refresh token to cookies
            res.cookie('refreshToken', newRefreshToken, {
                httpOnly: true,
                secure: false, // When deploying, set to true
                path: '/', // Don't require
                sameSite: 'strict'
            });

            res.status(200).json({ accessToken: newAccessToken });
        });
    },
    // LOG OUT
    logoutUser: async (req, res) => {
        res.clearCookie('refreshToken');
        refreshTokens = refreshTokens.filter(
            (token) => token !== req.cookies.refreshToken
        );
        res.status(200).json('Logged out!');
    }
};

module.exports = authController;
