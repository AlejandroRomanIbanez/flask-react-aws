import React, { useEffect } from 'react';
import { useHistory } from 'react-router-dom';
import axios from 'axios';
import { useDispatch } from 'react-redux';
import { ACCOUNT_INITIALIZE } from '../../../../store/actions';
import configData from '../../../../config';

const SalesforceCallback = () => {
    const history = useHistory();
    const dispatch = useDispatch();

    useEffect(() => {
        const handleAuthResponse = async () => {
            try {
                const params = new URLSearchParams(window.location.search);
                const code = params.get('code');
                const session_token = localStorage.getItem('session_token');
                if (!code || !session_token) {
                    console.error("Authorization code or session token not found.");
                    return;
                }

                const response = await axios.get(configData.API_SERVER + 'users/salesforce/callback', {
                    params: { code, session_token }
                });
                console.log('Response from /api/users/salesforce/callback:', response.data);

                if (response.data.success) {
                    const { access_token, id_token, refresh_token, user } = response.data;

                    localStorage.setItem('access_token', access_token);
                    localStorage.setItem('id_token', id_token);
                    localStorage.setItem('refresh_token', refresh_token);
                    localStorage.setItem('user', user);

                    dispatch({
                        type: ACCOUNT_INITIALIZE,
                        payload: { isLoggedIn: true, user: user, token: access_token }
                    });

                    history.push('/dashboard/default');
                } else {
                    console.error('Authentication failed:', response.data.msg);
                }
            } catch (error) {
                console.error('Error handling auth response', error);
            }
        };

        handleAuthResponse();
    }, [history, dispatch]);

    return <div>Loading...</div>;
};

export default SalesforceCallback;
