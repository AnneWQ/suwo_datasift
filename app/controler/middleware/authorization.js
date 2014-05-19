var User = require('../../model/user'),
    crypto = require('crypto');

exports.isAuthenticated = function(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        req.flash('info', ['Please login first']);
        res.redirect("/login");
    }
};

exports.userExist = function(req, res, next) {
    User.count({
        email: req.body.email
    }, function(err, count) {
        if (count === 0) {
            next();
        } else {
            req.flash('info', ['User already exists, please login']);
            res.redirect("/login");
        }
    });
};

exports.rememberMe = function(req, res, next) {
    // Issue a remember me cookie if the option was checked
    if (!req.body.remember_me) {
        return next();
    }

    crypto.randomBytes(32, function(ex, buf) {
        var token = buf.toString('hex');
        req.user.rememberme = token;
        req.user.save(function(err, user) {
            if (err) return next(err);
            res.cookie('remember_me', token, {
                path: '/',
                httpOnly: true,
                maxAge: 604800000
            });
            next();
        });
    });
};
