// src/components/GoogleSignIn.js
import React from 'react';

const GoogleSignIn = () => {
    const signInWithGoogle = () => {
        const redirectUri = `${process.env.REACT_APP_COGNITO_DOMAIN}/oauth2/authorize?response_type=code&client_id=${process.env.REACT_APP_COGNITO_APP_CLIENT_ID}&redirect_uri=${process.env.REACT_APP_COGNITO_REDIRECT_URI}&identity_provider=Google&scope=email+openid+profile`;        window.location.href = redirectUri;
    };

    return (
        <button onClick={signInWithGoogle}>Sign in with Google</button>
    );
};

export default GoogleSignIn;
