var admin = require('../../model/admin'),
    DataSift = require('datasift-node');

//TODO keep the username and api key safe
var user = 'xgfd',
    apikey = '76c29191a4c9e458c9689ff1fcec2c17',
    ds = new DataSift(user, apikey);

module.exports.executeCSDL = function(req, res) {
    var csdl = req.body.csdl;
    var ds = new DataSift(user, apikey);
    ds.connect();
    ds.on('connect', function() {
        console.log('connected');
        //TODO validate before compiling
        // compile the CSDL so we get a hash back
        ds.compile({
            'csdl': csdl //'interaction.content contains "test"'
        }, function(err, response) {
            // check for errors

            if (err) {
                req.flash('error', [err.message]);
            }

            if (response && response.hash) {
                console.log('Compiled CSDL : ' + response);

                var user = req.user;

                if (user.quota.used + response.dpu > user.quota.cap) {
                    req.flash('error', ['Not enough credit']);
                    return res.redirect('/datasift/stream');
                }

                user.quota.used += response.dpu;

                user.save(function(err) {
                    if (err) throw err;
                });

                // great we have our hash now we can subscribe to our stream
                //ds.subscribe(response.hash);
                req.flash('info', ['DPU credit should have been updated. You will be redirected to stream subscription in the production version.']);
                res.redirect('/profile');
            } else {
                req.flash('error', ['Invalid CSDL']);
                res.redirect('/datasift/stream');
            }
        });
    });

    // Our error checker
    ds.on('error', function(error) {
        console.log('Connection errored with: ' + error);
        if (err) {
            req.flash('error', [err.message]);
        }
    });

    // This is where we get the data from our stream
    ds.on('interaction', function(data) {
        console.log('Recieved data', data);
    });
};

module.exports.compileCSDL = function(req, res, next) {
    var csdl = req.query.csdl;
    ds.compile({
        'csdl': csdl //'interaction.content contains "test"'
    }, function(err, response) {
        if (err) return next(err);

        if (response && response.hash) {
            req.csdl = response;
        }

        next();
    });
};
