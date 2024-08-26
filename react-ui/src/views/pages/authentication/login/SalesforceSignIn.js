import React from 'react';
import { Button } from '@material-ui/core';
import axios from 'axios';
import configData from '../../../../config';

const SalesforceSignIn = () => {
    const signInWithSalesforce = async () => {
        try {
            const response = await axios.get(`${configData.API_SERVER}/users/salesforce/login`);
            const { auth_url, session_token } = response.data;

            // Save the session token in localStorage
            localStorage.setItem('session_token', session_token);

            // Redirect to Salesforce authorization URL
            window.location.href = auth_url;
        } catch (error) {
            console.error('Error during Salesforce login:', error);
        }
    };

    return (
        <Button 
            onClick={signInWithSalesforce} 
            style={{
                padding: '10px 20px',
                backgroundColor: '#00A1E0',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '16px'
            }}
        >
            Sign in with Salesforce
        </Button>
    );
};

export default SalesforceSignIn;
