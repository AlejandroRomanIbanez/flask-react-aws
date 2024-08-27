import React from 'react';
import { Button } from '@material-ui/core';
import axios from 'axios';
import configData from '../../../../config';
import { FaSalesforce } from 'react-icons/fa6';

const SalesforceSignIn = () => {
    const signInWithSalesforce = async () => {
        try {
            const response = await axios.get(`${configData.API_SERVER}/users/salesforce/login`);
            const { auth_url, code_verifier } = response.data;

            // Save the code_verifier in localStorage
            localStorage.setItem('code_verifier', code_verifier);

            // Redirect to Salesforce authorization URL
            window.location.href = auth_url;
        } catch (error) {
            console.error('Error during Salesforce login:', error);
        }
    };

    return (
        <Button
            onClick={signInWithSalesforce}
            fullWidth
            startIcon={<FaSalesforce size={24} />}
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
            Salesforce
        </Button>
    );
};

export default SalesforceSignIn;