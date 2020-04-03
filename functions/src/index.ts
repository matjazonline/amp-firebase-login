import * as functions from 'firebase-functions';

const admin = require('firebase-admin');
const cookie = require('cookie');
// TODO set origin
const cors = require('cors')({ origin: true });
const projectId = 'amp-firebase-login';
const cookieName = "session";

const serviceAccount = require("../amp-firebase-login-firebase-adminsdk-td106-dc0085a53e.json");
admin.initializeApp({ projectId: projectId, credential: admin.credential.cert(serviceAccount) });

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
export const loggedin = functions.https.onRequest((req, res) => {
    cors(req, res, () => {
        res.set('Access-Control-Allow-Credentials', 'true');
        res.set('Access-Control-Allow-Methods', 'GET');
        const cookiesString: any = req.headers && req.headers.cookie ? req.headers.cookie : null;

        if (!cookiesString) {
            res.status(200).send('{"loggedIn": false}');
            return;
        }
        const valuePairs = cookiesString.split(';');
        const cookieTokenValue = valuePairs.map((vp: any) => vp.split('=')).find((valPairArr: string[]) => {
            return valPairArr[0].trim() === cookieName;
        });
        if (!cookieTokenValue) {
            res.status(200).send('{"loggedIn": false}');
            return;
        }
        const idToken = cookieTokenValue[1].trim();
        admin.auth().verifySessionCookie(idToken, true).then(
            function (decodedToken: any) {
                const uid = decodedToken.uid;
                res.status(200).send('{"loggedIn": ' + !!uid + '}');
            }).catch(function (e: any) {
                res.status(200).send(e.message);
            });
    });
})

export const sessionLogin = functions.https.onRequest((req, res) => {

    // res.set('Access-Control-Allow-Origin', 'http://localhost:5000');
    res.set('Access-Control-Allow-Origin', 'https://amp-firebase-login.web.app');
    res.set('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        // Send response to OPTIONS requests
        res.set('Access-Control-Allow-Methods', 'POST');
        res.set('Access-Control-Allow-Headers', 'Bearer, Content-Type');
        res.set('Access-Control-Max-Age', '3600');
        res.status(204).send(null);
        return
    }

    // cors(req, res, () => {
    // Get the ID token passed and the CSRF token.
    const idToken = req.body.data.idToken.trim();
    /*TODO how to get value on FE
    const csrfToken = req.body.csrfToken.toString();
    // Guard against CSRF attacks.
       if (csrfToken !== req.cookies.csrfToken) {
        res.status(401).send('UNAUTHORIZED REQUEST!');
        return;
    }*/
    //TODO check if same token already in cookies

    admin.auth().verifyIdToken(idToken).then((verifiedIdToken: any) => {
        // Only process if the user just signed in in the last 5 minutes.
        //TODO enable auth_time check
        // if ((new Date()).getTime() / 1000 - verifiedIdToken.auth_time < 5 * 60) {
        // Set session expiration to 5 days.
        const expiresIn = 60 * 60 * 24 * 5 * 1000;
        // Create the session cookie. This will also verify the ID token in the process.
        // The session cookie will have the same claims as the ID token.
        // To only allow session cookie setting on recent sign-in, auth_time in ID token
        // can be checked to ensure user was recently signed in before creating a session cookie.
        admin.auth().createSessionCookie(idToken, { expiresIn: expiresIn })
            .then((sessionCookie: any) => {
                //TODO this is not setting cookie from header - make httpOnly=true and set from server and remove .value in response
                const options: any = {
                    maxAge: expiresIn,
                    httpOnly: true,
                    secure: true,
                    sameSite: 'none',
                };
                // res.cookie('session', sessionCookie, options);
                // res.end(JSON.stringify({
                //     data: {
                //         status: 'success',
                //         value: sessionCookie,
                //         options: options
                //     }
                // }));
                const cki = cookie.serialize('session', sessionCookie, options);
                res.setHeader('Set-Cookie', cki);
                res.end(JSON.stringify({
                    data: {
                        status: 'success'
                    }
                }));

            }, (error: any) => {
                console.log('ERROR 1', error)
                res.status(401).send();
            });
        /*} else {
            //  logout and login to set session
            res.end(JSON.stringify({
                data: {
                    status: 'token not recent'
                }
            }));
        }*/
    }, (error: any) => {
        console.log('ERROR 3')
        res.status(401).send();
    });
    // });
});

export const sessionLogout = functions.https.onRequest((req, res) => {
    //res.set('Access-Control-Allow-Origin', 'http://localhost:5000');
    res.set('Access-Control-Allow-Origin', 'https://amp-firebase-login.web.app');
    res.set('Access-Control-Allow-Credentials', 'true');
    console.log('L OUT')
    if (req.method === 'GET') {
        res.status(200).send('wrks');
        return
    }
    if (req.method === 'OPTIONS') {
        // Send response to OPTIONS requests
        res.set('Access-Control-Allow-Methods', 'POST');
        //res.set('Access-Control-Allow-Headers', 'Bearer, Content-Type');
        //res.set('Access-Control-Max-Age', '3600');
        res.status(204).send(null);
        return
    }
    // session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT
    const options: any = {
        maxAge: -999999,
        httpOnly: true,
        secure: true,
        sameSite: 'none',
    };
    const cki = cookie.serialize('session', '', options);
    res.setHeader('Set-Cookie', cki);
    res.status(200).send(JSON.stringify({
        data: {
            status: 'success'
        }
    }));
});
