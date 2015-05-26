/* Mimosa Node.JS Browsers Check  
https://github.com/rfdslabs/Mimosa-Framework

Ex: node browser.js fileWithUserAgents
bash$ node parser.js file
┌────────────────┬──────────┐
│ Name           │ Quantity │
├────────────────┼──────────┤
│ Chrome 41      │ 618      │
├────────────────┼──────────┤
│ Chrome 31      │ 19       │
├────────────────┼──────────┤
│ Chrome 39      │ 263      │
├────────────────┼──────────┤
│ IE 7           │ 166      │
├────────────────┼──────────┤
│ IE 8           │ 230      │
├────────────────┼──────────┤
│ IE 9           │ 34       │
├────────────────┼──────────┤
│ Chrome 40      │ 13       │
├────────────────┼──────────┤
│ IE 11          │ 147      │



*/

var readline = require('readline');
var UAParser = require('ua-parser-js');
var Table    = require('cli-table');
var fs       = require('fs');
var _        = require('lodash');

var parser = new UAParser();
var uaArr  = [];
var lines  = 0;

var rl = readline.createInterface({
  input: fs.createReadStream('ua'),
  terminal: false
});

rl.on('line', function (line) {
  var result = parser.setUA(line).getResult();
  var found = _.find(uaArr, {
    browser: { name: result.browser.name, major: result.browser.major }
  });

  if (!found) {
    result.count = 0;
    uaArr.push(result);
    return;
  }

  found.count++;
  lines++;
});

rl.on('close', function () {
  var table = new Table({
    head: ['Name', 'Quantity']
  });
  uaArr.forEach(function (value, index) {
    if (value.browser.name) {
      table.push([
        value.browser.name + ' ' + value.browser.major,
        value.count
      ]);
    } else {
      table.push([
        'Not recognized',
        value.count
      ]);
    }
  });

  _.sortByAll(uaArr, ['name']);

  console.log(table.toString());
});
