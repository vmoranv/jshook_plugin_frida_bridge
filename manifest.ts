import {
  checkExternalCommand,
  toErrorResponse,
  toTextResponse,
} from '@jshookmcp/extension-sdk/bridges';
import {
  createExtension,
  getPluginBooleanConfig,
  loadPluginEnv,
} from '@jshookmcp/extension-sdk/plugin';
import type { ToolArgs, PluginLifecycleContext } from '@jshookmcp/extension-sdk/plugin';

loadPluginEnv(import.meta.url);

function generateFridaTemplate(hookType: string, functionName: string): string {
  const templates: Record<string, string> = {
    intercept: [
      `// Frida Interceptor template for: ${functionName}`,
      `Interceptor.attach(Module.getExportByName(null, '${functionName}'), {`,
      `  onEnter(args) {`,
      `    console.log('[+] ${functionName} called');`,
      `    console.log('    arg0:', args[0]);`,
      `    console.log('    arg1:', args[1]);`,
      `  },`,
      `  onLeave(retval) {`,
      `    console.log('[+] ${functionName} returned:', retval);`,
      `  }`,
      `});`,
    ].join('\n'),
    replace: [
      `// Frida Replace template for: ${functionName}`,
      `Interceptor.replace(Module.getExportByName(null, '${functionName}'),`,
      `  new NativeCallback(function() {`,
      `    console.log('[+] ${functionName} replaced');`,
      `    return 0;`,
      `  }, 'int', [])`,
      `);`,
    ].join('\n'),
    stalker: [
      `// Frida Stalker template for tracing: ${functionName}`,
      `const targetAddr = Module.getExportByName(null, '${functionName}');`,
      `Interceptor.attach(targetAddr, {`,
      `  onEnter(args) {`,
      `    this.tid = Process.getCurrentThreadId();`,
      `    Stalker.follow(this.tid, {`,
      `      events: { call: true, ret: false, exec: false },`,
      `      onCallSummary(summary) {`,
      `        for (const [addr, count] of Object.entries(summary)) {`,
      `          const sym = DebugSymbol.fromAddress(ptr(addr));`,
      `          if (sym.name) console.log(\`  \${sym.name}: \${count}x\`);`,
      `        }`,
      `      }`,
      `    });`,
      `  },`,
      `  onLeave() {`,
      `    Stalker.unfollow(this.tid);`,
      `  }`,
      `});`,
    ].join('\n'),
    module_export: [
      `// Frida Module Export enumeration`,
      `const exports = Module.enumerateExports('${functionName}');`,
      `console.log(\`[+] Found \${exports.length} exports in ${functionName}\`);`,
      `exports.forEach((exp, i) => {`,
      `  console.log(\`  [\${i}] \${exp.type} \${exp.name} @ \${exp.address}\`);`,
      `});`,
    ].join('\n'),
  };

  return templates[hookType] ?? templates.intercept;
}

async function handleFridaBridge(args: ToolArgs) {
  const action = typeof args.action === 'string' ? args.action : 'guide';

  if (action === 'check_env') {
    return checkExternalCommand(
      'frida',
      ['--version'],
      'frida',
      'Install frida-tools (pip install frida-tools) and ensure frida is in PATH',
    );
  }

  if (action === 'generate_script') {
    const target = typeof args.target === 'string' ? args.target : '<process_name>';
    const hookType = typeof args.hookType === 'string' ? args.hookType : 'intercept';
    const functionName = typeof args.functionName === 'string' ? args.functionName : '<target_function>';
    const script = generateFridaTemplate(hookType, functionName);

    return toTextResponse({
      success: true,
      target,
      hookType,
      functionName,
      script,
      usage: `frida -p <PID> -l script.js  // or: frida -n "${target}" -l script.js`,
    });
  }

  if (action === 'guide') {
    return toTextResponse({
      success: true,
      guide: {
        actions: ['check_env', 'generate_script', 'guide'],
        workflow: [
          '1. Use process_find / process_find_chromium to locate target process',
          '2. Use frida_bridge(action="generate_script") to generate hook template',
          '3. Save script and run frida CLI to inject it',
        ],
        links: ['https://frida.re/docs/home/', 'https://frida.re/docs/javascript-api/'],
      },
    });
  }

  return toErrorResponse('frida_bridge', new Error('Unsupported action'), { action });
}

export default createExtension('io.github.vmoranv.frida-bridge', '0.1.0')
  .compatibleCore('>=0.1.0')
  .profile(['full'])
  .allowHost(['127.0.0.1', 'localhost', '::1'])
  .allowCommand('frida')
  .allowTool('frida_bridge')
  .configDefault('plugins.frida-bridge.enabled', true)
  .metric('frida_bridge_calls_total')
  .tool(
    'frida_bridge',
    'Frida helper bridge. Actions: check_env, generate_script, guide.',
    {
      action: { type: 'string', enum: ['check_env', 'generate_script', 'guide'], default: 'guide' },
      target: { type: 'string' },
      hookType: { type: 'string', enum: ['intercept', 'replace', 'stalker', 'module_export'], default: 'intercept' },
      functionName: { type: 'string' },
    },
    async (args) => handleFridaBridge(args),
  )
  .onLoad((ctx) => { ctx.setRuntimeData('loadedAt', new Date().toISOString()); })
  .onValidate((ctx: PluginLifecycleContext) => {
    const enabled = getPluginBooleanConfig(ctx, 'frida-bridge', 'enabled', true);
    if (!enabled) return { valid: false, errors: ['Plugin disabled by config'] };
    return { valid: true, errors: [] };
  });
