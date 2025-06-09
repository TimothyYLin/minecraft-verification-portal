import axios from 'axios';

//TODO: Move this to .env
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

const api = axios.create({
    baseURL: API_BASE_URL,
    withCredentials: true
});

export const setAuthToken = (token) => {
    if (token){
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
        delete api.defaults.headers.common['Authorization'];
    }
};

// On failure of an API call due to expired token, try to refresh token then automatically re-request
api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && 
            error.response.data?.code === 'TOKEN_EXPIRED' &&
            !originalRequest._retry
        ){
            originalRequest._retry = true;
            try{
                console.log('Access token expired. Attemping to refresh...');
                const { data } = await api.post('/refresh-token');

                const loginSuccessEvent = new CustomEvent('loginSuccess', { detail: data.token });
                window.dispatchEvent(loginSuccessEvent);

                originalRequest.headers['Authorization'] = `Bearer ${data.token}`;
                return api(originalRequest);
            }catch(refreshError){
                const logoutEvent = new Event('logout');
                window.dispatchEvent(logoutEvent);
                return Promise.reject(new Error('Your session has expired. Please log in again.'));
            }
        }

        const apiError = new Error(error.response?.data?.message || error.response?.data?.error || 'An API error occurred.');
        apiError.code = error.response?.data?.code;
        return Promise.reject(apiError);
    }
);

export const registerUser = async (email, password) => (await api.post('/register', { email, password })).data;
export const loginUser = async (email, password) => (await api.post('/login', { email, password })).data;
export const resendVerificationEmail = async (email) => (await api.post('/resend-verification', { email })).data;
export const linkMinecraftUsername = async (mc_username) => (await api.post('/mc-username', { mc_username })).data;
export const logoutUser = () => api.post('/logout');

export default api;
