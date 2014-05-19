var User = require('../app/model/user'),
    Auth = require('../app/controler/middleware/authorization'),
    quota = require('../app/controler/middleware/quota'),
    async = require('async'),
    ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn,
    config = require('./config'),
    Recaptcha = require('recaptcha').Recaptcha,
    pbk = config.recap_pbk,
    prk = config.recap_prk,
    pass = require('../app/controler/middleware/reset_pass'),
    logger = require('../app/util/logger'),
    crypto = require('crypto');

module.exports = function(app, passport) {

    app.get('/', function(req, res) {
        if (req.isAuthenticated()) {
            res.render("index", {
                info: req.flash('info'),
                error: req.flash('error'),
                user: req.user
            });
        } else {
            res.render("index", {
                info: req.flash('info'),
                error: req.flash('error')
            });
        }
    });

    //signup
    app.get('/signup', function(req, res) {
        var recaptcha = new Recaptcha(pbk, prk);
        res.render('signup', {
            layout: false,
            recaptcha_form: recaptcha.toHTML()
        });
    });

    app.post('/signup', Auth.userExist, function(req, res, next) {

        var data = {
            remoteip: req.connection.remoteAddress,
            challenge: req.body.recaptcha_challenge_field,
            response: req.body.recaptcha_response_field
        };

        var recaptcha = new Recaptcha(pbk, prk, data);
        recaptcha.verify(function(success, error_code) {
            if (success) {
                //TODO form validation
                User.signup(req.body.firstname, req.body.lastname, req.body.email, req.body.passwd, function(err, user) {
                    if (err) return next(err);

                    req.login(user, function(err) {
                        if (err) return next(err);

                        return res.redirect('/');
                    });
                });
            } else {
                req.flash('error', ['Recaptcha not valid.']);
                res.redirect('/signup');
            }
        });
    });

    //authentication
    app.get('/login', function(req, res) {
        res.render("login", {
            info: req.flash('info'),
            error: req.flash('error')
        });
    });

    app.post('/login', passport.authenticate('local', {
        //successReturnToOrRedirect: '/',
        failureRedirect: "/login",
        failureFlash: true
    }), Auth.rememberMe, function(req, res) {
        var url = '/datasift/stream';
        console.log(req.session);
        if (req.session && req.session.returnTo) {
            url = req.session.returnTo;
            delete req.session.returnTo;
        }
        return res.redirect(url);
    });

    app.post('/auth/soton', passport.authenticate('ldapauth', {
        failureRedirect: '/login',
        failureFlash: true
        //successReturnToOrRedirect: '/'
    }), Auth.rememberMe, function(req, res) {
        var url = '/datasift/stream';
        console.log(req.session);
        if (req.session && req.session.returnTo) {
            url = req.session.returnTo;
            delete req.session.returnTo;
        }
        return res.redirect(url);
    });

    //profile
    app.get('/profile', ensureLoggedIn('/login'), function(req, res) {
        User.findOne({
            email: req.user.email
        }, function(err, user) {

            if (err) {
                req.flash('error', [err.message]);
            }

            //view parameters
            var parameter = {};

            if (user) parameter.user = {
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
                quota: user.quota
            };

            parameter.error = req.flash('error');
            parameter.info = req.flash('info');
            res.render('profile', parameter);
        });
    });

    //update user profile
    app.post('/profile', ensureLoggedIn('/login'), function(req, res) {
        var oldpw = req.body.oldpw,
            newpw = req.body.newpw,
            fn = req.body.fn,
            ln = req.body.ln,
            org = req.body.org,
            email = req.user.email;
        if (newpw) {
            User.isValidUserPassword(email, oldpw, function(err, user, msg) {
                if (err) {
                    req.flash('error', [err.message]);
                    return res.redirect(req.get('referer'));
                }

                if (!user) {
                    req.flash('error', [msg.message]);
                    return res.redirect(req.get('referer'));
                }

                User.updateProfile(user, newpw, fn, ln, org, function(err, user) {
                    if (err) {
                        req.flash('error', [err.message]);
                        return res.redirect(req.get('referer'));
                    } else {
                        req.flash('info', ['Profile updated']);
                        return res.redirect(req.get('referer'));
                    }
                });
            });
        } else {
            User.findOne({
                'email': email
            }, function(err, user) {
                if (err) {
                    req.flash('error', [err.message]);
                    return res.redirect(req.get('referer'));
                }

                User.updateProfile(user, null, fn, ln, org, function(err, user) {
                    if (err) {
                        req.flash('error', [err.message]);
                        return res.redirect(req.get('referer'));
                    } else {
                        req.flash('info', ['Profile updated']);
                        return res.redirect(req.get('referer'));
                    }
                });

            });
        }
    });

    //reseting password
    //TODO rewrite reset_pass to middleware
    app.get('/profile/reset-pass', function(req, res) {
        var tk = req.query.tk;
        if (!tk) {
            req.flash('error', ['Password reset token is missing, please request again.']);
            return res.redirect('/login');
        }

        res.render('reset-pass', {
            'tk': tk
        });
    });

    app.post('/profile/reset-pass', function(req, res) {
        var tk = req.body.tk,
            confpass = req.body.confirm,
            newpass = req.body.password;

        if (newpass !== confpass) {
            req.flash('error', ['Passwords do not match']);
            return res.redirect(req.get('referer'));
        }

        pass.resetPass(tk, newpass, function(err, user) {
            if (err || !user) {
                req.flash('error', [err.message || 'User not found']);
                return res.redirect('/login');
            }
            req.login(user, function(err) {
                if (err) {
                    req.flash('error', [err.message]);
                    req.flash('error', ['An error occured, please login manually.']);
                    return res.redirect('/login');
                }
                res.redirect('/');
            });
        });
    });

    app.get('/profile/forgot-pass', function(req, res) {
        res.render('forgot-pass', {
            'info': req.flash('info'),
            'error': req.flash('error')
        });
    });

    app.post('/profile/forgot-pass', function(req, res) {
        pass.forgotPass(req.body.email, 'http://' + req.host + ':' + app.get('port') + '/profile/reset-pass', function(err, response) {
            if (err) {
                req.flash('error', [err.message]);
                return res.redirect('/profile/forgot-pass');
            }
            req.flash('info', ['Please check your email to reset your password.']);
            res.redirect('/login');
        });
    });

    app.get('/logout', function(req, res) {
        res.clearCookie('remember_me');
        req.logout();
        res.redirect('/');
    });

    //quota 
    app.get('/datasift/stream', function(req, res) {
        res.render('csdl', {
            error: req.flash('error'),
            info: req.flash('info'),
            user: req.user
        });
    });

    app.post('/datasift/stream', ensureLoggedIn('/login'), quota.executeCSDL);

    app.get('/datasift/validate', ensureLoggedIn('/login'), function(req, res) {


    });

    app.get('/datasift/dpu', ensureLoggedIn('/login'), quota.compileCSDL, function(req, res) {
        if (req.user) {
            var qt = req.user.quota,
                csdl = req.csdl;
            csdl.remain = qt.cap - qt.used - csdl.dpu;
        }
        res.send(csdl);
    });

};
