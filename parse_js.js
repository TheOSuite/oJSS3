const fs = require('fs');
const esprima = require('esprima');

// Check command-line argument
if (process.argv.length < 3) {
  console.error('Usage: node parse_js.js <input_file>');
  process.exit(1);
}

const inputFile = process.argv[2];

// S3 bucket pattern
const s3Pattern = /(?:https?:\/\/)?(?:[a-z0-9\-]+\.)?s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com\/([a-z0-9\-]+)|(?:https?:\/\/)?([a-z0-9\-]+)\.s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com|(?:https?:\/\/)?s3\.amazonaws\.com\/([a-z0-9\-]+)|(?:https?:\/\/)?([a-z0-9\-]+)\.s3-website[.-][a-z0-9\-]+\.amazonaws\.com/gi;

// URL pattern for endpoints
const urlPattern = /(?:https?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+/gi;

function extractEndpoints(node, endpoints = new Set()) {
  if (!node) return endpoints;

  // Extract string literals and template literals
  if (node.type === 'Literal' && typeof node.value === 'string') {
    if (urlPattern.test(node.value) || s3Pattern.test(node.value)) {
      endpoints.add(node.value);
    }
  } else if (node.type === 'TemplateLiteral') {
    node.quasis.forEach(quasi => {
      if (quasi.value && quasi.value.raw && (urlPattern.test(quasi.value.raw) || s3Pattern.test(quasi.value.raw))) {
        endpoints.add(quasi.value.raw);
      }
    });
  } else if (node.type === 'ObjectExpression') {
    // Extract object properties that might be URLs or buckets
    node.properties.forEach(prop => {
      if (prop.value && prop.value.type === 'Literal' && typeof prop.value.value === 'string') {
        if (urlPattern.test(prop.value.value) || s3Pattern.test(prop.value.value)) {
          endpoints.add(prop.value.value);
        }
      }
    });
  }

  // Recursively traverse child nodes
  for (let key in node) {
    if (node[key] && typeof node[key] === 'object') {
      extractEndpoints(node[key], endpoints);
    }
  }

  return endpoints;
}

try {
  const code = fs.readFileSync(inputFile, 'utf-8');
  const ast = esprima.parseScript(code, { tolerant: true }); // Tolerant mode for malformed JS
  const endpoints = extractEndpoints(ast);
  console.log(JSON.stringify([...endpoints]));
} catch (error) {
  console.error(`Error parsing ${inputFile}: ${error.message}`);
  process.exit(1);
}
