import ConsulDiscoveryService, { IConnectionParams, ILogger, LOG_PREFIX } from '../src'
import { EventEmitter } from 'events'

interface IConsulClientMock {
  watch: (method: any, options: any) => void
  health: () => any
}

class consulClientMockEmmiter extends EventEmitter {
  end() {
    return
  }
}

class consulClientMock implements IConsulClientMock {
  _host: string
  _port: string

  constructor(
    host: string,
    port: string
  ) {
    this._host = host
    this._port = port
  }

  watch(
    method,
    options
  ) {
    return new consulClientMockEmmiter()
  }

  health() {
    return {
      service: () => {}
    }
  }

}

const onChangeResponse: any = [
  {
    Service: {
      Address: '0.0.0.0',
      Port: '8888'
    }
  }
]

const testParams: IConnectionParams = {
  host: '0.0.0.0',
  port: '8888'
}

const expectedError = 'test error'

const fakeLogger: ILogger = {
  error() {},
  warn() {},
  log() {},
  info() {},
  debug() {throw new Error()}
}

describe('ConsulServiceDiscovery', () => {
  test('on change', async () => {
    expect.assertions(1)
    const discoveryService = new ConsulDiscoveryService(
      testParams,
      consulClientMock
    )
    const serviceConnectionParams = discoveryService.getConnectionParams('testService')
    const instantWathcer = discoveryService.instancesWatcher['testService']

    instantWathcer.on('change', () => {})
    instantWathcer.emit('change', onChangeResponse)
    expect(serviceConnectionParams).resolves.toEqual(testParams)
  }, 3000)

  test('on error', async () => {
    expect.assertions(1)
    const discoveryService = new ConsulDiscoveryService(
      testParams,
      consulClientMock
    )
    const serviceConnectionParams = discoveryService.getConnectionParams('testService')
    const instantWathcer = discoveryService.instancesWatcher['testService']
    instantWathcer.on('error', () => {})
    for (let i = 0; i <= 20; i++) {
      instantWathcer.emit('error', expectedError)
    }
    expect(serviceConnectionParams).rejects.toEqual(undefined)
  }, 3000)

  describe('constructor', () => {
    it('returns proper instance', () => {
      const service = new ConsulDiscoveryService(
        testParams,
        consulClientMock
      )

      expect(service).toBeInstanceOf(ConsulDiscoveryService)
      expect(service.getConnectionParams).not.toBeUndefined()
    })

    it('supports context configuration', () => {
      const spy = jest.spyOn(fakeLogger, 'debug')
      ConsulDiscoveryService.configure({logger: fakeLogger})

      new ConsulDiscoveryService(
        testParams,
        consulClientMock
      ).init('foo')

      expect(spy).toHaveBeenCalledWith(LOG_PREFIX, 'initialized');
    })
  })
})
