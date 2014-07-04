var mongoose = require('mongoose'),
    LocalStrategy = require('passport-local').Strategy,
    LDAPStrategy = require('passport-ldapauth').Strategy,
    RememberMeStrategy = require('passport-remember-me').Strategy,
    crypto = require('crypto'),
    User = mongoose.model('User');

module.exports = function(passport, config) {

    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        User.findOne({
            _id: id
        }, function(err, user) {
            done(err, user);
        });
    });

    passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
    }, function(email, password, done) {
        User.isValidUserPassword(email, password, done);
    }));

    var ldapOpts = {
        server: {
            url: 'ldaps://nlbldap.soton.ac.uk',
            searchBase: 'ou=User,dc=soton,dc=ac,dc=uk',
            adminDn: '',
            adminPassword: '',
            verbose: true,
            searchFilter: '(cn={{username}})',
            searchAttributes: ['displayName', 'mail', 'sn', 'givenName', 'cn']
        },
        //usernameField: Field name where the username is found, defaults to username
        //passwordField: Field name where the password is found, defaults to password
    };

    passport.use(new LDAPStrategy(ldapOpts, function(user, done) {
        User.findOrCreateSotonUser(user, done);
    }));

    passport.use(new RememberMeStrategy(consumeRememberMeToken, issueRememberMeToken));
};

function consumeRememberMeToken(token, done) {
    User.findOne({
        rememberme: token
    }, function(err, user) {
        if (err) return done(err, null);
        if (!user) return done(null, false, {
            message: 'No remembered user found'
        });

        user.rememberme = null;
        user.save(done);
    });
}

function issueRememberMeToken(user, done) {
    crypto.randomBytes(32, function(ex, buf) {
        var token = buf.toString('hex');
        user.rememberme = token;
        user.save(function(err, user) {
            if (err) return done(err);
            done(null, token);
        });
    });
}
