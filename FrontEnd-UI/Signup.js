import React, { useState } from 'react'
import { BrowserRouter, Redirect, Route } from 'react-router-dom'
import { connect } from 'react-redux'
import PropTypes from 'prop-types'

import { register } from '../actions/adminAuthAction'
import Alert from '../layout/Alert'
import Dashboard from './Dashboard'

const Signup = ({ register, isAuthenticated }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
  });

  const { username, email, password } = formData;

  const onChange = e =>
    setFormData({ ...formData, [e.target.name]: e.target.value })

  const onSubmit = async e => {
    e.preventDefault()

    register({ username, email, password });
  };

  //Redirect if logged  in 
  if (isAuthenticated) {
    return <Redirect to='/dashboard' />
  }

  return (
    <BrowserRouter>
      <Route path="/dasboard" component={Dashboard} />

      <div className="container-fluid">
        
        <center>
          <div className="signin center" style={{ zIndex: 9999, position: 'relative', opacity: '0.8',  marginTop:'10%'}}>
            <div className="card animate fadeLeft black " style={{ width:'50%', margin:'auto', border:'3px solid #07575B'}}>
              <div className="card-content white-text black " >
                <form onSubmit={e => onSubmit(e)}>
                  <h1 className="h3 mb-3 font-weight-normal white-text" >Register</h1>
                  <Alert />
                  <br />
                  <div className="form-group" >
                    <input
                      type="username"
                      className="form-control white-text "
                      name="username"
                      placeholder="Username "
                      value={username}
                      onChange={e => onChange(e)}
                      required
                    />
                  </div>
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
                  <button
                    type="submit"
                    className="btn btn-lg btn-primary btn-block"
                    style={{  opacity: '1' }}
                  >
                    Signup
                  </button>
                </form>
              </div>
            </div>
          </div>
        </center>
      </div>
    </BrowserRouter>
  )
}

Signup.propTypes = {
  register: PropTypes.func.isRequired,
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated
})

export default connect(mapStateToProps, { register })(Signup)
