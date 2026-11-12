npm i -D esbuild
npx esbuild node_modules/pkijs/build/index.js --bundle --format=iife --global-name=pkijs --target=es6
--outfile=resources/pkijs.bundle.js
npx esbuild node_modules/asn1js/build/index.js --bundle --format=iife --global-name=asn1js --target=es6
--outfile=resources/asn1js.bundle.js
 
