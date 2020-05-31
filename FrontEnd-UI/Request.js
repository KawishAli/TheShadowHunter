import React, { Component } from 'react';
// import './App.css'
import axios from 'axios';
import PostData from './response.json';
class Request extends Component {
  render() {
    return (
      <div>
        <h1>Our data is</h1>
        {PostData.map(postDetail => {
          return <h1>{postDetail}</h1>;
        })}
      </div>
    );
  }
}
export default Request;
