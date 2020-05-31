import React, { Component } from 'react';
import { BrowserRouter, Route } from 'react-router-dom';
import LineChart from './LineChart';
import BarChart from './BarChart';
import './dashboard.css';
import PieChart from './PieChart';
import DoughnutChart from './DoughnutChart';
import HorizontalBar from './HorizontalBar';

import PropTypes from 'prop-types'
import {connect} from 'react-redux'
import Navigation from './Navigation'
import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
import Radarchart from './RadarChart';

class Dashboard extends Component {
  render() {
    return (
      <BrowserRouter>
        <Route path='/navigation' component={Navigation} />
        <div className='app'>
        {this.props.role === "admin" ? <Navigation/>:(this.props.role === "manager" ? <NavigationManager/>:(this.props.role === "submanager"?<NavigationSubManager/>:null ) )}
          {/* <!-- Navbar goes here --> */}
          <div className='row'>

            <div className='col s12 m8 l9 offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}
              <div className='row'>
                <div className='col s12 m6 l3'>
                  <div className='card text-white bg-primary o-hidden h-100'>
                    <div className='card-body'>
                      <div className='card-body-icon'>
                        <i className='fas fa-fw fa-list' />
                      </div>
                      <div className='mr-5'>New Emails!</div>
                    </div>
                    <a
                      className='card-footer text-white clearfix small z-1'
                      href='#ee'
                    >
                      <span className='float-left'>View Details</span>
                      <span className='float-right'>
                        <i className='fas fa-angle-right' />
                      </span>
                    </a>
                  </div>
                </div>
                <div className='col s12 m6 l3 '>
                  <div className='card text-white bg-warning o-hidden h-100'>
                    <div className='card-body'>
                      <div className='card-body-icon'>
                        <i className='fas fa-fw fa-list' />
                      </div>
                      <div className='mr-5'>New Logs!</div>
                    </div>
                    <a
                      className='card-footer text-white clearfix small z-1'
                      href='#ee'
                    >
                      <span className='float-left'>View Details</span>
                      <span className='float-right'>
                        <i className='fas fa-angle-right' />
                      </span>
                    </a>
                  </div>
                </div>
                <div className='col s12 m6 l3 '>
                  <div className='card text-white bg-success o-hidden h-100'>
                    <div className='card-body'>
                      <div className='card-body-icon'>
                        <i className='fas fa-fw fa-shopping-cart' />
                      </div>
                      <div className='mr-5'>New Deception Alerts!</div>
                    </div>
                    <a
                      className='card-footer text-white clearfix small z-1'
                      href='#ee'
                    >
                      <span className='float-left'>View Details</span>
                      <span className='float-right'>
                        <i className='fas fa-angle-right' />
                      </span>
                    </a>
                  </div>
                </div>
                <div className='col s12 m6 l3 '>
                  <div className='card text-white bg-danger o-hidden h-100'>
                    <div className='card-body'>
                      <div className='card-body-icon'>
                        <i className='fas fa-fw fa-life-ring' />
                      </div>
                      <div className='mr-5'>Check Routing Configuration </div>
                    </div>
                    <a
                      className='card-footer text-white clearfix small z-1'
                      href='#ee'
                    >
                      <span className='float-left'>View Details</span>
                      <span className='float-right'>
                        <i className='fas fa-angle-right' />
                      </span>
                    </a>
                  </div>
                </div>
              </div>

              <div className='row'>
                <div className='col s12 m6 l6 '>
                  <div className='card text-white  o-hidden white h-100'>
                    <div className='card-body'>
                      <BarChart />
                    </div>
                  </div>
                </div>
             

             
                <div className='col s12 m6 l6 '>
                  <div className='card text-white  o-hidden white h-100'>
                    <div className='card-body'>
                      <LineChart />
                     
                    </div>
                  </div>
                </div>
                </div>

             

              
              <div className='row'>
                <div className='col s12 m3 l3 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                      <HorizontalBar></HorizontalBar>
                    </div>
                  </div>
                </div>
              
                <div className='col s12 m3 l3 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                    <HorizontalBar></HorizontalBar>
                    </div>
                  </div>
                </div>
                <div className='col s12 m3 l3 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                    <HorizontalBar></HorizontalBar>
                    </div>
                  </div>
                </div>
                <div className='col s12 m3 l3 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                    <HorizontalBar></HorizontalBar>
                    </div>
                  </div>
                </div>
              </div>
              <div className='row'>
                <div className='col s12 m4 l4 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                      <PieChart />
                    </div>
                  </div>
                </div>
              
                <div className='col s12 m4 l4 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                      <DoughnutChart />
                    </div>
                  </div>
                </div>
                <div className='col s12 m4 l4 '>
                  <div className='card text-white o-hidden white h-100'>
                    <div className='card-body'>
                      <Radarchart></Radarchart>
                    </div>
                  </div>
                </div>
               
              </div>
{/* <button href="/Addrole"> add </button> */}
             
            </div>
          </div>
        </div>
      </BrowserRouter>
    );
  }
}
Dashboard.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(Dashboard)
