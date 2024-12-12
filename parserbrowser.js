#!/usr/bin/env node
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
// Mimosa Node.JS Browsers Check  
// https://github.com/rfdslabs/Mimosa-Framework

const readline = require('readline');
const UAParser = require('ua-parser-js');
const Table = require('cli-table');
const fs = require('fs');
const _ = require('lodash');

// Get the input file from command-line arguments
const inputFile = process.argv[2];
if (!inputFile) {
  console.error('Usage: node browser.js <fileWithUserAgents>');
  process.exit(1);
}

// Check if the file exists
if (!fs.existsSync(inputFile)) {
  console.error(`Error: File '${inputFile}' not found.`);
  process.exit(1);
}

const parser = new UAParser();
const uaArr = [];
let lines = 0;

const rl = readline.createInterface({
  input: fs.createReadStream(inputFile),
  terminal: false,
});

rl.on('line', (line) => {
  const result = parser.setUA(line).getResult();
  const found = _.find(uaArr, {
    browser: { name: result.browser.name, major: result.browser.major },
  });

  if (!found) {
    result.count = 1;
    uaArr.push(result);
  } else {
    found.count++;
  }

  lines++;
});

rl.on('close', () => {
  const sortedData = _.sortBy(uaArr, [
    (entry) => entry.browser.name || '',
    (entry) => parseInt(entry.browser.major || '0', 10),
  ]);

  const table = new Table({
    head: ['Name', 'Quantity'],
  });

  sortedData.forEach((value) => {
    const browserName = value.browser.name ? `${value.browser.name} ${value.browser.major}` : 'Not recognized';
    table.push([browserName, value.count || 0]);
  });

  console.log(`Processed ${lines} lines.`);
  console.log(table.toString());
});
