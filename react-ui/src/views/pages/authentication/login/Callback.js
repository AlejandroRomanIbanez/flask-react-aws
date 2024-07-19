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

        const refreshToken = async () => {
            try {
                const response = await axios.post(configData.API_SERVER + 'users/refresh-token', {}, { withCredentials: true });
                if (response.data.success) {
                    return {
                        accessToken: response.data.access_token,
                        idToken: response.data.id_token,
                    };
                }
            } catch (error) {
                console.error('Error refreshing token', error);
            }
            return null;
        };
        const handleAuthResponse = async () => {
            try {
                console.log('Making request to /api/users/authenticate-with-cookies');
                const response = await axios.get(configData.API_SERVER + 'users/authenticate-with-cookies', { withCredentials: true });
                console.log('Response from /api/users/authenticate-with-cookies:', response.data);

                if (response.data.success) {
                    const { token, id_token, user } = response.data;
                    console.log("Received tokens and user info", response.data);

                    // Dispatch authentication state
                    dispatch({
                        type: ACCOUNT_INITIALIZE,
                        payload: { isLoggedIn: true, user: user, token: token }
                    });
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
