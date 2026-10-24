import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export function createMessageStore(filePath) {
  return {
    async read() {
      try {
        const contents = await readFile(filePath, 'utf8');
        const messages = JSON.parse(contents);
        if (!Array.isArray(messages)) throw new Error('Message store must contain a JSON array.');
        return messages;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await mkdir(path.dirname(filePath), { recursive: true });
        await writeFile(filePath, '[]\n', 'utf8');
        return [];
      }
    },

    async write(messages) {
      await mkdir(path.dirname(filePath), { recursive: true });
      const temporaryPath = `${filePath}.tmp`;
      await writeFile(temporaryPath, `${JSON.stringify(messages, null, 2)}\n`, 'utf8');
      await rename(temporaryPath, filePath);
    },
  };
}
