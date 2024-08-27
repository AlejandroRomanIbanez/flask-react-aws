// src/components/GoogleSignIn.js
import React from 'react';
import { Button } from '@material-ui/core';
import { makeStyles } from '@material-ui/styles';
import { FcGoogle } from 'react-icons/fc';

const useStyles = makeStyles({
    googleButton: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#4285F4',
        color: '#fff',
        padding: '10px 20px',
        textTransform: 'none',
        fontSize: '14px',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
        borderRadius: '4px',
        transition: 'background-color 0.3s',
        '&:hover': {
            backgroundColor: '#357ae8',
        },
        '& .google-icon': {
            marginRight: '8px',
        },
    },
});

const GoogleSignIn = () => {
    const classes = useStyles();

    const signInWithGoogle = () => {
        const redirectUri = `${process.env.REACT_APP_COGNITO_DOMAIN}/oauth2/authorize?response_type=code&client_id=${process.env.REACT_APP_COGNITO_APP_CLIENT_ID}&redirect_uri=${process.env.REACT_APP_COGNITO_REDIRECT_URI}&identity_provider=Google&scope=email+openid+profile`;
        window.location.href = redirectUri;
    };

    return (
        <Button
            onClick={signInWithGoogle}
            fullWidth
            startIcon={<FcGoogle size={24} />}
            sx={{
                padding: '10px',
                backgroundColor: 'transparent',
                border: '1px solid #7A869A',
                color: '#2E3B55',
                textTransform: 'none',
                fontSize: '16px',
                fontWeight: 'bold',
                borderRadius: '8px',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                '&:hover': {
                    backgroundColor: '#E0E4E8',
                },
            }}
        >
            Google
        </Button>
    );
};

export default GoogleSignIn;
