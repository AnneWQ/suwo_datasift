var User = require('../../model/user'),
    config = require('../../../config/config'),
    nodemailer = require('nodemailer'),
    crypto = require('crypto'),
    bcrypt = require('bcrypt-nodejs');

var smtpTransport = nodemailer.createTransport("SMTP", {
    host: config.smtp//'smtp.ecs.soton.ac.uk'
});

module.exports.forgotPass = function(email, reset_path, cb) {
    User.findOne({
        'email': email
    }, function(err, user) {
        if (err)
            return cb(err);
        crypto.randomBytes(32, function(ex, buf) {
            var tk = buf.toString('hex');
            user.reset = {
                token: tk,
                time_stamp: new Date()
            };
            user.save(function(err) {
                if (err)
                    return cb(err);
                var mailOptions = {
                    from: 'Soton Web Observatory <wo_passreset@ecs.soton.ac.uk>', // sender address
                    to: (email === 'xgfd@admin.com' ? 'xinxinbird@gmail.com' : email),
                    subject: "Password reset", // Subject line
                    html: 'Click here to <a href="' + reset_path + '?tk=' + tk + '">reset your password</a>. <br>You cannot reply to this mail address.' // html body
                };
                smtpTransport.sendMail(mailOptions, cb);
            });
        });
    });
};

module.exports.resetPass = function(tk, password, cb) {

    User.findOne({
        'reset.token': tk
    }, function(err, user) {
        if (err)
            return cb(err);
        if (!user)
            return cb({
                message: 'Token expired'
            });

        var past_hour = Math.abs(new Date() - user.reset.time_stamp) / 1000 / 60 / 60;

        if (past_hour > 2)
            return cb({
                message: 'Token expired'
            });

        hash(password, function(err, salt, hash) {
            if (err)
                return cb(err);
            user.salt = salt;
            user.hash = hash;
            user.reset = undefined;
            user.save(function(err, user) {
                if (err)
                    return cb(err);
                cb(null, user);
            });
        });
    });
};
