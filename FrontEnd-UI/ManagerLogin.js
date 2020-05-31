import React, { useState } from 'react'
import { BrowserRouter, Redirect, Route } from 'react-router-dom'
import { connect } from 'react-redux'
import PropTypes from 'prop-types'

import { login } from '../actions/managerAuthAction'
import Alert from '../layout/Alert'
import Dashboard from './Dashboard'
// import Signup from './Signup'

const ManagerLogin = ({ login, isAuthenticated, token, role }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const {  email, password } = formData;

  const onChange = e =>
    setFormData({ ...formData, [e.target.name]: e.target.value })

  const onSubmit = async e => {
    e.preventDefault()

    login({ email, password });
  };

  //Redirect if logged  in 
  if (token && isAuthenticated && role === "manager") {
    return <Redirect to='/managerdashboard' />
  }

  return (
    <BrowserRouter>
      <Route path="/dasboard" component={Dashboard} />
      {/* <Route path="/signup" component={Signup} /> */}

      <div className="container-fluid">
        
        <center>
        
          <div className="signin center" style={{ zIndex: 9999, position: 'relative', opacity: '0.8',  marginTop:'10%'}}>
          <h2 className="center black-text">Welcome to Shadow Hunters</h2>
          <h4 className="center black-text">Manager Panel</h4>
            <div className="card animate fadeLeft black " style={{ width:'50%', margin:'auto', border:'3px solid #07575B'}}>
              <div className="card-content white-text black " >
                <form onSubmit={e => onSubmit(e)}>
                  <h1 className="h3 mb-3 font-weight-normal white-text" style={{  opacity: '1' }}>Sign In</h1>
                  <Alert />
                  <br />
                  <div className="form-group" style={{  opacity: '1' }}>
                    <input
                      type="email"
                      className="form-control white-text "
                      name="email"
                      placeholder="Email Address"
                      value={email}
                      onChange={e => onChange(e)}
                      required
                    />
                  </div>
                  <div className="form-group" style={{  opacity: '1' }}>
                    <input
                      type="password"
                      className="form-control white-text "
                      name="password"
                      placeholder="Password"
                      value={password}
                      onChange={e => onChange(e)}
                      required
                    />
                  </div>
                  <center>
                  <button
                    type="submit"
                    className="btn btn-lg btn-primary btn-block center"
                    style={{  opacity: '1' , width:"30%"}}
                  >
                    Login
                  </button>
                  </center>
                  <br></br>
                  <p>Go to Admin Panel  <a href="/login"> Click Here</a></p>
                  <br></br>
                  <p>Go to Sub Manager Panel  <a href="/submanagerlogin"> Click Here</a></p>
                  
                  
                </form>
              </div>
            </div>
          </div>
        </center>
      </div>
    </BrowserRouter>
  )
}

ManagerLogin.propTypes = {
  login: PropTypes.func.isRequired,
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps, { login })(ManagerLogin)
