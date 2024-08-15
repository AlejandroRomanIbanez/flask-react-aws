import React, { useEffect } from 'react';
import { useHistory } from 'react-router-dom';
import axios from 'axios';
import { useDispatch } from 'react-redux';
import { ACCOUNT_INITIALIZE } from '../../../../store/actions';
import configData from '../../../../config';

const Callback = () => {
    const history = useHistory();
    const dispatch = useDispatch();

    useEffect(() => {
        const handleAuthResponse = async () => {
            try {
                const params = new URLSearchParams(window.location.search);
                const code = params.get('code');
                if (!code) {
                    console.error("Authorization code not found in the URL.");
                    return;
                }

                const response = await axios.get(configData.API_SERVER + 'users/callback', { params: { code } });
                console.log('Response from /api/users/callback:', response.data);

                if (response.data.success) {
                    const { access_token, id_token, refresh_token, user } = response.data;

                    // Store tokens in localStorage
                    localStorage.setItem('access_token', access_token);
                    localStorage.setItem('id_token', id_token);
                    localStorage.setItem('refresh_token', refresh_token);
                    localStorage.setItem('user', user);

                    // Dispatch authentication state
                    dispatch({
                        type: ACCOUNT_INITIALIZE,
                        payload: { isLoggedIn: true, user: JSON.parse(user), token: access_token }
                    });

                    // Redirect to the desired route
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

export default Callback;
