const User = require('../models/User');

const userController = {
    // GET ALL USERS
    getAllUsers: async (req, res) => {
        try {
            const users = await User.find();
            res.status(200).json(users);
        } catch (err) {
            res.status(500).json(err);
        }
    },
    deleteUser: async (req, res) => {
        try {
            const user = await User.findById(req.params.id);

            res.status(200).json('Delete successfully!');
        } catch (err) {
            res.status(500).json(err);
        }
    }
};

module.exports = userController;
