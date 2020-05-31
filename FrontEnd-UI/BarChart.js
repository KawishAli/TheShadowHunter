import React, { Component } from 'react';
import { Bar} from 'react-chartjs-2';

const data = {
    labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July','August', 'September', 'October', 'November', 'December'],
    datasets: [
      {
        label: 'My First dataset',
        data: [65, 59, 66, 58, 55, 56, 66, 65, 57, 59, 67, 62],
        backgroundColor:[
            'rgb(107,142,35)', 
            'rgb(139,0,139)', 
            'rgb(199,21,133)', 
            'rgb(188,143,143)', 
            'rgb(178,34,34)', 
            'rgb(255,160,122)', 
            'rgb(32,178,170)', 
            'rgb(160,82,45)',
            'rgb(199,21,122)', 
            'rgb(139,59,139)',
            'rgb(255,140,122)', 
            'rgb(0,9,0)',    
        ],
        borderColor:[
          'rgb(107,142,35)', 
          'rgb(139,0,139)', 
          'rgb(199,21,133)', 
          'rgb(188,143,143)', 
          'rgb(178,34,34)', 
          'rgb(255,160,122)', 
          'rgb(32,178,170)', 
          'rgb(160,82,45)',
          'rgb(199,21,122)', 
          'rgb(139,59,139)',
          'rgb(255,140,122)', 
          'rgb(0,9,122)',   

          ]
      }
    ]
  };

class BarChart extends Component {
  
    render() { 
      return ( 
            <div className="center bar">
        <Bar
          data={data}
          options={{
            maintainAspectRatio: false
          }}
        />
      </div>
                  
          
      );
    }
    }
export default BarChart;